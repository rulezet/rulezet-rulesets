rule sig_20160823_f59335062e106e07e8cc453bb1f7cb79 {
  meta:
    description = "datamaliciousorder - file 20160823_f59335062e106e07e8cc453bb1f7cb79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52d02dd1646caf59bd67476c519dbad1ce81d1bbb9069ca564c309ef32b8e742"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}