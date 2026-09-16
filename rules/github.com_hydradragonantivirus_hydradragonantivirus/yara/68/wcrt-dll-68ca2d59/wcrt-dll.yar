rule wcrt_dll {
  meta:
    author      = "PEiD"
    description = "WCRT Library (Visual C++) DLL Method 1 -> Jibz"
    group       = "17"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 7D 0C 01 75 ?? A1 ?? ?? ?? ?? 85 C0 74 ?? FF D0 85 C0 75 ?? 6A FE EB ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

  condition:
    $a0
}