rule upx_dll2 {
  meta:
    author      = "PEiD"
    description = "UPX 0.80 - 1.24 DLL -> Markus & Laszlo"
    group       = "BoB"
    function    = "0"

  strings:
    $a0 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB }

  condition:
    $a0
}