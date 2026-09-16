rule sig_20160823_f50dbc9ba71d9ddc1f6cdc95c658d876 {
  meta:
    description = "datamaliciousorder - file 20160823_f50dbc9ba71d9ddc1f6cdc95c658d876.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02d6cc3e903346898a1af4af47a1e326989721468a8b8bd71b9dbe9e03ec804f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}