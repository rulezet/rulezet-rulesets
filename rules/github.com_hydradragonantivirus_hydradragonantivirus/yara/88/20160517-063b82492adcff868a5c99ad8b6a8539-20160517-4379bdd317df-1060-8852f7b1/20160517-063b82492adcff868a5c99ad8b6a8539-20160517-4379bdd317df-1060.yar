rule _20160517_063b82492adcff868a5c99ad8b6a8539_20160517_4379bdd317df_1060 {
  meta:
    description = "datamaliciousorder - from files 20160517_063b82492adcff868a5c99ad8b6a8539.js, 20160517_4379bdd317dff4bcf5340761de69d29f.js, 20160517_cbd0391c2f6a67afd2ce4acaa1814e7a.js, 20160517_d9ce54b999482793b055f3f9f4038f7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7112db26419cae86b98ec211753ff620cde977de427022abfdfbead5bca8c709"
    hash2       = "798139cb8f06512ec42d9d0e0941c6c983c65be0454354b93d7b078644348a7f"
    hash3       = "76169b91497f4df46dfd53ab8ad79c4578d6e1da622cf3bed987f8917085ef33"
    hash4       = "ab7336097831aa2f33becaaf139c268513f16d73c49290d55bb49b07bce4cb84"

  strings:
    $s1 = "var nConverts1 /* C  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* C  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* C  */;};" fullword ascii
    $s4 = "batch =/* C  */ \"R\" + \"esponseB\"/* C  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "enjoy1 /* C  */ /* C  */= true;/* C  */" fullword ascii
    $s6 = "var enjoy1 /* C  */ = false;" fullword ascii
    $s7 = "could = /* C  */(/* C  */\"noitisop\").split(''/* C  */).reverse(/* C  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}