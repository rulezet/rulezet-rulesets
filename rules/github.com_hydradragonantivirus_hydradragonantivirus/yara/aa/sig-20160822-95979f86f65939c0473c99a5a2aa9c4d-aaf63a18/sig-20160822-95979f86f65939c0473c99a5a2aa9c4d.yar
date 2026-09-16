rule sig_20160822_95979f86f65939c0473c99a5a2aa9c4d {
  meta:
    description = "datamaliciousorder - file 20160822_95979f86f65939c0473c99a5a2aa9c4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96f5a234956da4a8319d3433b4b703caeef3d5673bd8ebff5296cf4014085ea6"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}