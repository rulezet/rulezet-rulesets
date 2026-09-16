rule js_splitting_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    version     = "0.1"
    description = "These are commonly used to split up JS code"
    weight      = 2

  strings:
    $magic = "%PDF"
    $js    = /\/JavaScript/
    $s0    = "getAnnots"
    $s1    = "getPageNumWords"
    $s2    = "getPageNthWord"
    $s3    = "this.info"

  condition:
    $magic at 0 and $js and 1 of ($s*)
}