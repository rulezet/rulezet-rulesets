rule SplashBitmap1_00_WithUnpackCode___BoB_TeamPEiD {
  meta:
    author      = "PEiD"
    description = "Splash Bitmap 1.00 (With Unpack Code) -> BoB / Team PEiD"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }

  condition:
    $a0
}