rule sig_20160224_c91c47d07dd88963cc141d31aec682f3 {
  meta:
    description = "datamaliciousorder - file 20160224_c91c47d07dd88963cc141d31aec682f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cbadfa2fdba30c80e9a9cbb90fc37eadc14f2676a8f4790d2c5b80b7af04cc2"

  strings:
    $s1 = "    var arbitratebIY = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[askanceypX](surreptitiousRJ3);" fullword ascii
    $s3 = "var fractiousxHO = function() {" fullword ascii
    $s4 = "function btoa(tribunalaRK, perorationHwQ, junketkJB, ensconcehiL, stipulateYic, genesishrX, veraciousTeC, mordantdaN, enigmatOW)" ascii
    $s5 = "var arrogateYcB = function(microcosmmwz) {" fullword ascii
    $s6 = "function btoa(tribunalaRK, perorationHwQ, junketkJB, ensconcehiL, stipulateYic, genesishrX, veraciousTeC, mordantdaN, enigmatOW)" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}