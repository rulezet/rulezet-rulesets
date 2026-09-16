rule sig_20160823_17d8f0321c7207b179453f54e173093b {
  meta:
    description = "datamaliciousorder - file 20160823_17d8f0321c7207b179453f54e173093b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f87c64717db62259baf7f5a5afa16157ff14239db545a2c08da3cb4b790262f"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}