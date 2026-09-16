rule Trojan_Danger_Trojan_GenericKD_72677122_277_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_277_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef15f39348fe19dd91499b4bef756b8f749e6ef47b249decd86e42d94436d126"

  strings:
    $s1 = "Running procedure 'file-pat-save-internal' failed: %s" fullword ascii
    $s2 = "Drawable to export" fullword ascii
    $s3 = "The URI of the file to export the image in" fullword ascii
    $s4 = "New Gimp patterns can be created by exporting them in the appropriate place with this plug-in." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}