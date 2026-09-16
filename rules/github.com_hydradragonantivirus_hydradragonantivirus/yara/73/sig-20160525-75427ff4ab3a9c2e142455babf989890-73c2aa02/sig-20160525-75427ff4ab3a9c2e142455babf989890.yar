rule sig_20160525_75427ff4ab3a9c2e142455babf989890 {
  meta:
    description = "datamaliciousorder - file 20160525_75427ff4ab3a9c2e142455babf989890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f6a8f87abac73baf7dfbc3aea75ff36b14ba28b84e29d18d2b864ba3d0c6bb0"

  strings:
    $s1 = "neth rav\\n;\"07x\\\\ttHn\" = ssorcah rav\\n;\"17x\\\\eR\" = tsilslianbmuhtoh rav\\n;\"e2x\\\\tseu\" = cthh rav\\n;\"13x\\\\e2x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}