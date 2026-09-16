rule warning_rtf_objupdate {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 2
    revision   = "1"
    date       = "Nov 20 2017"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2017. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_exploit"
    desc       = "update RTF object may load malicious content"

  strings:
    $header_xml = "{\\rt" nocase
    $upd        = "\\objupdate" nocase

  condition:
    all of them
}