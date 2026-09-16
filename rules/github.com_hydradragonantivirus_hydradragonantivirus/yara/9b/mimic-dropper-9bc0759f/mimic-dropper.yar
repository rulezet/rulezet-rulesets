rule Mimic_dropper {
  meta:
    author      = "rivitna"
    family      = "ransomware.mimic.windows"
    description = "Mimic ransomware dropper"
    severity    = 10
    score       = 100

  strings:
    $h = {
      37 7A 61 2E 65 78 65 20 78 20 2D 79 20 2D 70
      3? 3? 3? 3? [8-12] 3? 3? 3? 3?
      20 45 76 65 72 79 74 68 69 6E 67 36 34 2E 64 6C 6C 22
    }

  condition:
    ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
    (filesize > 1500KB) and (filesize < 10000KB) and
    (
      $h in (100000..200000)
    )
}