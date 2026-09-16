rule sig_20160823_7dc44f456a274a2cb81c6c0bd3e99099 {
  meta:
    description = "datamaliciousorder - file 20160823_7dc44f456a274a2cb81c6c0bd3e99099.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4f668b910f6ed1cad0f40ffcbf8f622858be4f538441271d848a2f0fe41d07"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}