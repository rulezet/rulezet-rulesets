rule sig_20160519_6b9c425a5a3543c80360d78c38e97e35 {
  meta:
    description = "datamaliciousorder - file 20160519_6b9c425a5a3543c80360d78c38e97e35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c6aa45ed96a292bab56bf17bdd7c719b69c436104daf45e574e8b2a67c59530"

  strings:
    $s1  = "        inborn[(finish + \"o\"+(\"proboscis\",\"metamorphosis\",\"nitrogenous\",\"belfast\",\"correct\",\"jordan\",\"undermine\"" ascii
    $s2  = "accumulate = ((\"favourites\", \"wrote\", \"furlough\", \"favorite\", \"celery\", \"aircraft\", \"sxSefVocDKV\") + \"jReMqhKhUg" ascii
    $s3  = "allegory(\"aHR0cDovLw==\".airily4()+\"\\u0061\\u0070\\u0061\\u0072\\u0074\\u006D\\u0061\\u006E\\u0069\\u0070\\u0072\\u0065\\u006" ascii
    $s4  = "var sulphuric=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".airily4())&&labor[\"c3RhdHVz\".airily4()] +\"\"==\"MjAw\".airily4(" ascii
    $s5  = "var socket = [tanzania, gavin,recognition,  \"\"+\".\"+(\"terminating\",\"aquarium\",\"cadet\",\"boxer\",\"calibre\",\"patter\"," ascii
    $s6  = "weasel = ((\"yeoman\", \"futures\", \"upsetting\", \"urine\", \"ENolIFLA\") + \"mDFDWiTveR\").airily2();" fullword ascii
    $s7  = "finish = ((\"selfishly\", \"esprit\", \"norwegian\", \"abandoned\", \"ptTrzUGB\") + \"PloKXrynVDc\").airily2();" fullword ascii
    $s8  = "rally = rally+ socket.shift();" fullword ascii
    $s9  = "var swimming = socket.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.airily = function () {" fullword ascii
    $s11 = "String.prototype.airily2 = function () {" fullword ascii
    $s12 = "String.prototype.airily4 = function() {" fullword ascii
    $s13 = "dropsy = this;" fullword ascii
    $s14 = "        inborn[(finish + \"o\"+(\"proboscis\",\"metamorphosis\",\"nitrogenous\",\"belfast\",\"correct\",\"jordan\",\"undermine\"" ascii
    $s15 = "for (var i in wizard){dropsy = dropsy.replace(i, wizard[i]);}" fullword ascii
    $s16 = "var sulphuric=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".airily4())&&labor[\"c3RhdHVz\".airily4()] +\"\"==\"MjAw\".airily4(" ascii
    $s17 = ",\"blacks\",\"libertine\",\"kerosene\",\"imbecile\",\"08\"), accumulate)] = 0;" fullword ascii
    $s18 = "allegory(\"aHR0cDovLw==\".airily4()+\"\\u0061\\u0070\\u0061\\u0072\\u0074\\u006D\\u0061\\u006E\\u0069\\u0070\\u0072\\u0065\\u006" ascii
    $s19 = "function allegory(squad, talisman) {" fullword ascii
    $s20 = "var labor = new brake(swimming[0]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}