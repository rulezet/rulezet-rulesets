rule sig_20160822_3e22299bd9b2ac4bb880ed38a9c29bf3 {
  meta:
    description = "datamaliciousorder - file 20160822_3e22299bd9b2ac4bb880ed38a9c29bf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75796d7e24c07da26cfdd7709b33dc8eb2f6ba7bfa45774c6b878946ec0f8501"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}