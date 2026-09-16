rule sig_20160224_8b85cec9afc42b2b99e88315a3af24c9 {
  meta:
    description = "datamaliciousorder - file 20160224_8b85cec9afc42b2b99e88315a3af24c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "540995dcfefbc73f4effcadffd9427eb72548509f3663cefd1cea5ebb4abd866"

  strings:
    $s1 = "    var coaxWpg = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "function btoa(pithyGla, tribunalBkJ, burgeonCua, jibek2n, cavaliervZA, rendoCB, pontificals8j, apostaterHF, imperturbableMcQ, co" ascii
    $s3 = "        return WScript[zealoteus](interpolateALk);" fullword ascii
    $s4 = "function btoa(pithyGla, tribunalBkJ, burgeonCua, jibek2n, cavaliervZA, rendoCB, pontificals8j, apostaterHF, imperturbableMcQ, co" ascii
    $s5 = "var harryQkB = function(rankleyT7) {" fullword ascii
    $s6 = "var canonxvG = function() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}