rule _20161025_76272cdc8626a2b0adb95693cb3f7f64_20161025_d29340905dce_204 {
  meta:
    description = "datamaliciousorder - from files 20161025_76272cdc8626a2b0adb95693cb3f7f64.js, 20161025_d29340905dcec0c5bcd18c28dcb197ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed3bfd301121aa0671f385754aa69ac15feb00d915c1b2d6b9811385c21bb01c"
    hash2       = "44f35a90daed8b27d792d8d490372a1c493bc2e43b0596113749936827eba57b"

  strings:
    $s1  = "var siarik = new Function(\"seldereycomfortFROG2_a5,seldereycomfortFROG2HORDA5\", 'return seldereycomfortFROG2_bChosteck.velMRAD" ascii
    $s2  = "var siarik = new Function(\"seldereycomfortFROG2_a5,seldereycomfortFROG2HORDA5\", 'return seldereycomfortFROG2_bChosteck.velMRAD" ascii
    $s3  = "seldereycomfortFROG2rampart[seldereycomfortFROG2promises + \"\"]((seldereycomfortFROG2StrokaParam2,\"ru\") +\"\"+seldereycomfort" ascii
    $s4  = "seldereycomfortFROG2undefilled.seldereycomfortFROG2sameOrN = function(seldereycomfortFROG2param1, seldereycomfortFROG2param2) {" fullword ascii
    $s5  = "seldereycomfortFROG2Native.seldereycomfortFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereycomfortFROG2$type" ascii
    $s6  = "seldereycomfortFROG2undefilled.angle = function(seldereycomfortFROG2p) {" fullword ascii
    $s7  = "seldereycomfortFROG2Native.seldereycomfortFROG2genericize=function(a,b,c){c&&a[b]||\"function\"!=typeof a.prototype[b]||(a[b]=fu" ascii
    $s8  = "seldereycomfortFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s9  = "seldereycomfortFROG2Native.seldereycomfortFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereycomfortFROG2$type" ascii
    $s10 = "        } while (seldereycomfortFROG2XCOP < seldereycomfortFROG2len && seldereycomfortFROG2c3 == -1);" fullword ascii
    $s11 = "        } while (seldereycomfortFROG2XCOP < seldereycomfortFROG2len && seldereycomfortFROG2c4 == -1);" fullword ascii
    $s12 = "        } while (seldereycomfortFROG2XCOP < seldereycomfortFROG2len && seldereycomfortFROG2ddDccC1 == -1);" fullword ascii
    $s13 = "function seldereycomfortFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s14 = "};seldereycomfortFROG2Native.seldereycomfortFROG2XCOPmplement = function(seldereycomfortFROG2objects, seldereycomfortFROG2proper" ascii
    $s15 = "if(seldereycomfortFROG2FrankSinatraLaa < 29999)return false;" fullword ascii
    $s16 = "function seldereycomfortFROGzapadniy2 (velSUyaWON) {" fullword ascii
    $s17 = "function seldereycomfortFROG2_a2(seldereycomfortFROG2gutter, seldereycomfortFROG2StrokaParam2) {" fullword ascii
    $s18 = "function seldereycomfortFROG_OOO_OOO(TT){" fullword ascii
    $s19 = "var seldereycomfortFROG2dodo = false;" fullword ascii
    $s20 = "function seldereycomfortFROGzapadniy(seldereycomfortFROGvostochniy) {" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}