rule _201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078be_1016 {
  meta:
    description = "datamaliciousorder - from files 201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078bea.js, 93b921e53498e0ce61fa8740e083f55a10d72b0b9a406cdb05a9860ffcc94eb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078bea"
    hash2       = "93b921e53498e0ce61fa8740e083f55a10d72b0b9a406cdb05a9860ffcc94eb9"

  strings:
    $s1  = "Array.prototype.om0l4d3 = function() {var hYiUrF = \\u0061\\u0072\\u0067\\u0075\\u006D\\u0065\\u006E\\u0074\\u0073; return this[" ascii
    $s2  = "Array.prototype.om0l4d3 = function() {var hYiUrF = \\u0061\\u0072\\u0067\\u0075\\u006D\\u0065\\u006E\\u0074\\u0073; return this[" ascii
    $s3  = "\\x65\")](\"bst\"),[\"us-\\x61\\x73\\x63\\x69\\x69\"]),function(){return m3MorYkAd[3][0];},function(){for(var p=0; p<m3MorYkAd[2" ascii
    $s4  = "YkAd[1][0]](\"\\x6D\\x69\\x63\\x72\\x6F\\x73\\x6F\\x66\\x74\\x2E\\x78\\x6D\\x6C\\x64\\x6F\\x6D\")[Array(\"create\\x45\\x6C\",\"" ascii
    $s5  = "'String[\"prototype\"].oS3Hm = function(){return [].s0fStu;}'.proc();" fullword ascii
    $s6  = "return k3tTlE0;}});}" fullword ascii
    $s7  = "oMut1 = [Array(WSH[m3MorYkAd[1][0]]([\"\\x61\\x64{0}\\x62\\x2E{1}\\x72\\x65{2}\"].om0l4d3(\"\\x6F\\x64\", \"\\x73\\x74\", \"\\x6" ascii
    $s8  = "oMut1 = [Array(WSH[m3MorYkAd[1][0]]([\"\\x61\\x64{0}\\x62\\x2E{1}\\x72\\x65{2}\"].om0l4d3(\"\\x6F\\x64\", \"\\x73\\x74\", \"\\x6" ascii
    $s9  = "ce\"](exp, function(k3tTlE0, k3tTlE1) { try{" fullword ascii
    $s10 = "String[\"prototype\"][\"\\x75\\x6E\\x64\\x65\\x66\\x69\\x6E\\x65\\x64\"] = function(xx, xy) {" fullword ascii
    $s11 = "var exp = /{(\\d+)}/g;var oMut1 = null;" fullword ascii
    $s12 = "return hYiUrF[k3tTlE1];}catch(ex){" fullword ascii

  condition:
    (uint16(0) == 0x7453 and (8 of them)
    ) or (all of them)
}