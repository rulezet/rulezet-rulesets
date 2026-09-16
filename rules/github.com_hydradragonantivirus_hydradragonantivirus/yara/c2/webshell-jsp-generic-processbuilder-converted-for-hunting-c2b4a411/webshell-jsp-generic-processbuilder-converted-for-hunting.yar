rule webshell_jsp_generic_processbuilder__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Generic JSP webshell which uses processbuilder to execute user input"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/07"
    score = 40

  strings:
    $exec   = "ProcessBuilder" fullword wide ascii
    $start  = "start" fullword wide ascii
    $input1 = "getParameter" fullword ascii wide
    $input2 = "getHeaders" fullword ascii wide
    $input3 = "getInputStream" fullword ascii wide
    $input4 = "getReader" fullword ascii wide
    $req1   = "request" fullword ascii wide
    $req2   = "HttpServletRequest" fullword ascii wide
    $req3   = "getRequest" fullword ascii wide

  condition:
    (filesize >= 2000 and filesize < 6000
    )
    and
    (any of ($input*) and any of ($req*)) and $exec and $start
}