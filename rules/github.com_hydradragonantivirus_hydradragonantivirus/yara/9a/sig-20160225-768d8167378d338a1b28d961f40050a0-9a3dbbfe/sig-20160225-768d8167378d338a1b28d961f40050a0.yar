rule sig_20160225_768d8167378d338a1b28d961f40050a0 {
  meta:
    description = "datamaliciousorder - file 20160225_768d8167378d338a1b28d961f40050a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd0066a14d7c5c793bd31f7ece847fa815b6fd2a983f9dd0276295d7ec93787d"

  strings:
    $s1 = "    var gustyWAj = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "var facilesVh = function(avaricet4G) {" fullword ascii
    $s3 = "var leagueaiN = function() {" fullword ascii
    $s4 = "function btoa(convinceSCI, peonwDJ, sanctionYll, vatRNk, attitudeRCn, squeamishww0, reactionaryNR9) {" fullword ascii
    $s5 = "    var treadtvc = function() {" fullword ascii
    $s6 = "    return treadtvc;" fullword ascii
    $s7 = "        return WScript[upbraiducH](scabbardl62);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}