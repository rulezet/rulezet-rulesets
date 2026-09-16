rule sig_20160517_108b47b40ca678ef7ada782b4f0ed9d4 {
  meta:
    description = "datamaliciousorder - file 20160517_108b47b40ca678ef7ada782b4f0ed9d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ded660bdb8874274fca05781d11e57f2ac15dc21de80adc2c063a0725ea46b1"

  strings:
    $s1 = "var cu4j='vynfoaayczltrp3onz jg4xzlsuyncflqjnnxipateggrkfdfhdfwv4ekcih3ktb4gvqv2viyif2t3=b3uuh\\'n3phztvrjr4cgxw12nhiweeirxngqfe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}