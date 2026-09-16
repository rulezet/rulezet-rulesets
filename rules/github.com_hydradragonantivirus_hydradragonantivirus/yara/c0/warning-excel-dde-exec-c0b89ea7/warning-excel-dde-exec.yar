rule warning_excel_dde_exec {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 5
    revision   = "1"
    date       = "Oct 10 2017"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2017. All rights reserved."
    tlp        = "white"
    sigtype    = "cryptam_exploit"
    desc       = "Embedded js"

  strings:
    $header_xml = "<?xml version=" nocase wide ascii
    $dde        = "instrText>DDE"

  condition:
    $header_xml and $dde
}