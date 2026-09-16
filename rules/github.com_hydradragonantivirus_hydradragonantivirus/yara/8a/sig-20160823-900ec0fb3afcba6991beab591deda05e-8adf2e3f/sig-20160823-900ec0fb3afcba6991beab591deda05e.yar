rule sig_20160823_900ec0fb3afcba6991beab591deda05e {
  meta:
    description = "datamaliciousorder - file 20160823_900ec0fb3afcba6991beab591deda05e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d8e0e3fdf17060e0522487a577975fe7d7b6e7a49f83d303501259b36916e8f"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}