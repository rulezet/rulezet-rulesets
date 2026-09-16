rule sig_20160823_674b58d621784c28be722e05886fa157 {
  meta:
    description = "datamaliciousorder - file 20160823_674b58d621784c28be722e05886fa157.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7785971940c1b4e3218c4b45cd968daa9a86b5d707b35b1d76d41fcd14990fd8"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}