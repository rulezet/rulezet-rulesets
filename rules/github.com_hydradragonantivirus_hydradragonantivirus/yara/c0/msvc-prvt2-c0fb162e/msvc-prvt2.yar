rule msvc_prvt2 {
  meta:
    author      = "PEiD"
    description = "Microsoft Visual C++ Private Version 2"
    group       = "15"
    function    = "0"

  strings:
    $a0 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }

  condition:
    $a0
}