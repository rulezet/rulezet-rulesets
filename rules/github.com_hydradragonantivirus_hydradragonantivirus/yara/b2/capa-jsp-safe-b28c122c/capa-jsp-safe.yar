rule capa_jsp_safe: WEBSHELL PROD {
  meta:
    description = "capa JSP tag"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/24"

  strings:
    $cjsp_short1 = "<%" ascii wide
    $cjsp_short2 = "%>" wide ascii
    $cjsp_long1  = "<jsp:" ascii wide
    $cjsp_long2  = /language=[\"']java[\"\']/ ascii wide
        $cjsp_long3  = "/jstl/core" ascii wide
    $cjsp_long4  = "<%@p" nocase ascii wide
    $cjsp_long5  = "<%@ " nocase ascii wide
    $cjsp_long6  = "<% " ascii wide
    $cjsp_long7  = "< %" ascii wide

  condition:
    $cjsp_short1 at 0 or
    any of ($cjsp_long*) or
    $cjsp_short2 in (filesize - 100..filesize) or
    (
      $cjsp_short2 and (
        $cjsp_short1 in (0..1000) or
        $cjsp_short1 in (filesize - 1000..filesize)
      )
    )
}