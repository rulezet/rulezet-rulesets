rule invalid_XObject_js_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    description = "XObject's require v1.4+"
    ref         = "https://blogs.adobe.com/ReferenceXObjects/"
    version     = "0.1"
    weight      = 2

  strings:
    $magic = "%PDF"
    $ver   = /%PDF-1\.[4-9]/

    $attrib0 = /\/XObject/
    $attrib1 = /\/JavaScript/

  condition:
    $magic at 0 and not $ver and all of ($attrib*)
}