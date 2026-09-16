rule warning_js_inzip {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 3
    revision   = "1"
    date       = "Oct 9 2017"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2017. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_exploit"
    desc       = "Embedded js"

  strings:
    $h1 = "PK"
    $s1 = { 2e 6a 73 0a 00 20 }
    $s2 = { 2e 6a 73 ad }

  condition:
    $h1 at 0 and all of ($s*)
}