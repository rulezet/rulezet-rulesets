rule sig_20160301_f851425c283892e3a26ac953d3ba5a93 {
  meta:
    description = "datamaliciousorder - file 20160301_f851425c283892e3a26ac953d3ba5a93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "716d4d3b26b03f822ece7d895f8ab5027a8909a167e33a32dfe9000a1cb54f31"

  strings:
    $s1 = "circleNormal = organismAccumulator[(\"\\u0064\" + \"\\u0069\\u0063\\u0074\" + \"ate\", function String.prototype.guideMotor() {" fullword ascii
    $s2 = "while(circleNormal[(\"po\\u0072t\", \"\\u0072ea\" + \"\\u0064\\u0079st\\u0061\" + \"t\\u0065\")] < 2 * 2) {" fullword ascii
    $s3 = "organismAccumulator = (((1 ^ 0) | (190, 0)), this);" fullword ascii
    $s4 = "} catch(cultureCaste) {};" fullword ascii

  condition:
    uint16(0) == 0x726f and
    all of them
}