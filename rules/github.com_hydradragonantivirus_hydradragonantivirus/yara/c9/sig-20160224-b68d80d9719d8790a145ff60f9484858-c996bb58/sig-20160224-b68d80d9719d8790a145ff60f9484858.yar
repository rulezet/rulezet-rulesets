rule sig_20160224_b68d80d9719d8790a145ff60f9484858 {
  meta:
    description = "datamaliciousorder - file 20160224_b68d80d9719d8790a145ff60f9484858.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e5f1eb6ea8c3246a4922f83d369d3108ef97b4bbb2e2d397b64c7e1cafdfa0d"

  strings:
    $s1 = "    var retrenchYTM = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[stratumgTD](forsakeNHV);" fullword ascii
    $s3 = "var jocundNb7 = function() {" fullword ascii
    $s4 = "var arrogatep78 = function(whetj2o) {" fullword ascii
    $s5 = "function btoa(tyroHAR, adulterateCW0, expiateGfd, waylayopu, suavityv98, charyNG9, infallibleDvm, stumpHNt, emendwik, inditee3X," ascii
    $s6 = "function btoa(tyroHAR, adulterateCW0, expiateGfd, waylayopu, suavityv98, charyNG9, infallibleDvm, stumpHNt, emendwik, inditee3X," ascii
    $s7 = "    return pathologicalefJ;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}