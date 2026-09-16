rule sig_20160224_646dd2607fc5438509b388a2f191a950 {
  meta:
    description = "datamaliciousorder - file 20160224_646dd2607fc5438509b388a2f191a950.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4621ce417cc451b76d80d7f07b286a494517ebf38813984472228c9e09cd22b2"

  strings:
    $s1  = "    var multitudeaxG = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2  = "        return WScript[plumbRk5](stentorianVcg);" fullword ascii
    $s3  = "var ominousfpw = function() {" fullword ascii
    $s4  = "function btoa(ambrosiaLm1, thrallRgy, harrowinghwQ, chastisekZ6, affablega7, acrimonyVPv, suffragex9B, emeticDgc, ellipsisBq8, b" ascii
    $s5  = "var encumbernYK = function(objectivedjj) {" fullword ascii
    $s6  = "    var malcontentsz3 = function() {" fullword ascii
    $s7  = "    malcontentsz3.prototype.kO8PwrUKTf = function(stentorianVcg) {" fullword ascii
    $s8  = "    return malcontentsz3;" fullword ascii
    $s9  = "    malcontentsz3.prototype.fR3oI8Y7Nu = function(stentorianVcg) {" fullword ascii
    $s10 = "function btoa(ambrosiaLm1, thrallRgy, harrowinghwQ, chastisekZ6, affablega7, acrimonyVPv, suffragex9B, emeticDgc, ellipsisBq8, b" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}