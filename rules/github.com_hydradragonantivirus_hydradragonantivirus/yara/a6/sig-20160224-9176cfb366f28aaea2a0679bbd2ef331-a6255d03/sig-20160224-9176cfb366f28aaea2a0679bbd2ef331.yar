rule sig_20160224_9176cfb366f28aaea2a0679bbd2ef331 {
  meta:
    description = "datamaliciousorder - file 20160224_9176cfb366f28aaea2a0679bbd2ef331.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "278a2b552969771fd220231c2dff61d9ffeefe08b3456d36e113ce5bb7841216"

  strings:
    $s1 = "    var pompFFg = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[chideKd4](cognateVLi);" fullword ascii
    $s3 = "var rebusvaN = function() {" fullword ascii
    $s4 = "var husbandryRig = function(sobGWQ) {" fullword ascii
    $s5 = "function btoa(gougeEid, punditoMY, sinecurej9r, veritableocJ, waivenwJ, buxomlqJ, musterqDq, homespuniqm) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}