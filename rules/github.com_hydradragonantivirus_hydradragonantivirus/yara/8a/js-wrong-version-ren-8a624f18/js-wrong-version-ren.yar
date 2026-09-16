rule js_wrong_version_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    description = "JavaScript was introduced in v1.3"
    ref         = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
    version     = "0.1"
    weight      = 2

  strings:
    $magic = "%PDF"
    $js    = /\/JavaScript/
    $ver   = /%PDF-1\.[3-9]/

  condition:
    $magic at 0 and $js and not $ver
}