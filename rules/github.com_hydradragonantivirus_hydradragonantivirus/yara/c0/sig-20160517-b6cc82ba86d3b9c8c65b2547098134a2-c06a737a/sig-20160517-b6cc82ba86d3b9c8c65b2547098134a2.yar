rule sig_20160517_b6cc82ba86d3b9c8c65b2547098134a2 {
  meta:
    description = "datamaliciousorder - file 20160517_b6cc82ba86d3b9c8c65b2547098134a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c312b8303f6ee146b22184669ccd805921b2ff43eeb8c27a6c983880b822b8c"

  strings:
    $s1  = "var postings=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".recover4())&&moiety[\"c3RhdHVz\".recover4()] +\"\"==\"MjAw\".recove" ascii
    $s2  = "var postings=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".recover4())&&moiety[\"c3RhdHVz\".recover4()] +\"\"==\"MjAw\".recove" ascii
    $s3  = "var delay = [generate, cited,mongolia,  \"\"+\".\"+(\"shooting\",\"protocol\",\"customize\",\"recant\",\"eight\",\"devon\",\"fea" ascii
    $s4  = "convulsion = ((\"convoy\", \"besiege\", \"sustainability\", \"pepper\", \"shdoEsKJjAQd\") + \"lJvpJIHrM\").recover2();" fullword ascii
    $s5  = "String.prototype.recover = function () {" fullword ascii
    $s6  = "var unrelated = delay.pop().split(\"" fullword ascii
    $s7  = "String.prototype.recover4 = function() {" fullword ascii
    $s8  = "String.prototype.recover2 = function () {" fullword ascii
    $s9  = "    altered.marines = altered.yeast[((\"employment\",\"contentious\",\"atmospheric\",\"vernal\",\"jungle\",\"microsoft\",\"fragm" ascii
    $s10 = "going = \"_F2_\";" fullword ascii
    $s11 = "weasel = ((\"cathedral\", \"interfaces\", \"vizier\", \"latter\", \"EwlRNXA\") + \"jdXbzWDF\").recover2();" fullword ascii
    $s12 = "superintendent[delay.shift()](somali, termination, true);JvGjOoehls = \"_F17_\";" fullword ascii
    $s13 = "foamy = ((\"lightning\", \"calculators\", \"mucous\", \"buffer\", \"pJhFUAziUboO\") + \"buMuqjFlX\").recover2();" fullword ascii
    $s14 = "var termination = 6/6;" fullword ascii
    $s15 = "function earned(cowboy, vacuum) {" fullword ascii
    $s16 = "suspect = this;" fullword ascii
    $s17 = "agedian\",\"deleterious\",\"roommate\",\"chronicles\",\"08\"), convulsion)] = 0;" fullword ascii
    $s18 = "var relative = superintendent[delay.shift()](delay.shift());" fullword ascii
    $s19 = "var energy = 0;" fullword ascii
    $s20 = "var generate = \"QWviolateN0aXZviolatelWE9iaviolatemVjdA=violate=\".recover4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}