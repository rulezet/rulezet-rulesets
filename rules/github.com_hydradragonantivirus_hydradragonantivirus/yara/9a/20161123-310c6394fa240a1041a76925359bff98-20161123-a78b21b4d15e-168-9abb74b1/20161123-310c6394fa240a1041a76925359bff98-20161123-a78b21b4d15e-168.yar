rule _20161123_310c6394fa240a1041a76925359bff98_20161123_a78b21b4d15e_168 {
  meta:
    description = "datamaliciousorder - from files 20161123_310c6394fa240a1041a76925359bff98.js, 20161123_a78b21b4d15e04e4338444387e93ef18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc4bd4beab36e4091ed52c92aa8ddf6da89931c240fc9e42ad72f77e567eec00"
    hash2       = "9ce740ccbbd1c112fa03a3be38ccf0072b8a905bf8569c07889ca2b0c020073d"

  strings:
    $s1  = " var POLKAOLKA500 = new Function(\"komonbarbyletgopartypathologicalFROG2_a5,komonbarbyletgopartypathologicalFROG2HORDA5\", 'retu" ascii
    $s2  = "        } while (komonbarbyletgopartypathologicalFROG2XCOP < komonbarbyletgopartypathologicalFROG2len && komonbarbyletgopartypat" ascii
    $s3  = "        } while (komonbarbyletgopartypathologicalFROG2XCOP < komonbarbyletgopartypathologicalFROG2len && komonbarbyletgopartypat" ascii
    $s4  = "        } while (komonbarbyletgopartypathologicalFROG2XCOP < komonbarbyletgopartypathologicalFROG2len && komonbarbyletgopartypat" ascii
    $s5  = "        } while (komonbarbyletgopartypathologicalFROG2XCOP < komonbarbyletgopartypathologicalFROG2len && komonbarbyletgopartypat" ascii
    $s6  = "function  komonbarbyletgopartypathologicalFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii
    $s7  = "komonbarbyletgopartypathologicalFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s8  = "komonbarbyletgopartypathologicalFROG2undefilled.angle = function(komonbarbyletgopartypathologicalFROG2p) {" fullword ascii
    $s9  = " var POLKAOLKA500 = new Function(\"komonbarbyletgopartypathologicalFROG2_a5,komonbarbyletgopartypathologicalFROG2HORDA5\", 'retu" ascii
    $s10 = "function  komonbarbyletgopartypathologicalFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s11 = "komonbarbyletgopartypathologicalFROG2undefilled.scale = function(komonbarbyletgopartypathologicalFROG2p, komonbarbyletgopartypat" ascii
    $s12 = "komonbarbyletgopartypathologicalFROG2Native.komonbarbyletgopartypathologicalFROG2XCOPmplement = function(komonbarbyletgopartypat" ascii
    $s13 = "function  komonbarbyletgopartypathologicalFROG2_bCho(T, D, C) {" fullword ascii
    $s14 = "function  komonbarbyletgopartypathologicalFROG2_a2(komonbarbyletgopartypathologicalFROG2gutter, komonbarbyletgopartypathological" ascii
    $s15 = "}catch(komonbarbyletgopartypathologicalSScssS){}" fullword ascii
    $s16 = "komonbarbyletgopartypathologicaloldBitch[komonbarbyletgopartypathologicalFROG2promises ]((komonbarbyletgopartypathologicalFROG2S" ascii
    $s17 = "if(komonbarbyletgopartypathologicalFROG2FrankSinatraLaa < 29989)return false;" fullword ascii
    $s18 = "if (komonbarbyletgopartypathologicalFROG2FrankSinatra[0]!= 77 || komonbarbyletgopartypathologicalFROG2FrankSinatra[1]!= 90)retur" ascii
    $s19 = "gopartypathologicalFROG2typize=function(a,b){a.type||(a.type=function(a){return komonbarbyletgopartypathologicalFROG2$type(a)===" ascii
    $s20 = "komonbarbyletgopartypathologicalFROG2undefilled.komonbarbyletgopartypathologicalFROG2sameOrN = function(komonbarbyletgopartypath" ascii

  condition:
    (uint16(0) == 0x7620 and (8 of them)
    ) or (all of them)
}