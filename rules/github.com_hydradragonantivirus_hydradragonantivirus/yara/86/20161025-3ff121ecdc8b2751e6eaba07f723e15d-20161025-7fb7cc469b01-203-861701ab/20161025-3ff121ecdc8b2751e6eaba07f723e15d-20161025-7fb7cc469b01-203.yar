rule _20161025_3ff121ecdc8b2751e6eaba07f723e15d_20161025_7fb7cc469b01_203 {
  meta:
    description = "datamaliciousorder - from files 20161025_3ff121ecdc8b2751e6eaba07f723e15d.js, 20161025_7fb7cc469b01f6b4750e191684389c07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ae653dd6ea6390201881ac6f36a2900a845695ec8408dfb76d2ad694ec8d4d2"
    hash2       = "3ae442c4e8c55fc8e72e36be928b4c2036d8c477d365ecce7934d52ad32fcdae"

  strings:
    $s1  = "var siarik = new Function(\"seldereyupstartFROG2_a5,seldereyupstartFROG2HORDA5\", 'return seldereyupstartFROG2_bChosteck.velMRAD" ascii
    $s2  = "var siarik = new Function(\"seldereyupstartFROG2_a5,seldereyupstartFROG2HORDA5\", 'return seldereyupstartFROG2_bChosteck.velMRAD" ascii
    $s3  = "seldereyupstartFROG2rampart[seldereyupstartFROG2promises + \"\"]((seldereyupstartFROG2StrokaParam2,\"ru\") +\"\"+seldereyupstart" ascii
    $s4  = "seldereyupstartFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s5  = "seldereyupstartFROG2Native.seldereyupstartFROG2genericize=function(a,b,c){c&&a[b]||\"function\"!=typeof a.prototype[b]||(a[b]=fu" ascii
    $s6  = "seldereyupstartFROG2undefilled.seldereyupstartFROG2sameOrN = function(seldereyupstartFROG2param1, seldereyupstartFROG2param2) {" fullword ascii
    $s7  = "seldereyupstartFROG2Native.seldereyupstartFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereyupstartFROG2$type" ascii
    $s8  = "seldereyupstartFROG2Native.seldereyupstartFROG2typize=function(a,b){a.type||(a.type=function(a){return seldereyupstartFROG2$type" ascii
    $s9  = "seldereyupstartFROG2undefilled.angle = function(seldereyupstartFROG2p) {" fullword ascii
    $s10 = "        } while (seldereyupstartFROG2XCOP < seldereyupstartFROG2len && seldereyupstartFROG2c3 == -1);" fullword ascii
    $s11 = "        } while (seldereyupstartFROG2XCOP < seldereyupstartFROG2len && seldereyupstartFROG2ddDccC1 == -1);" fullword ascii
    $s12 = "        } while (seldereyupstartFROG2XCOP < seldereyupstartFROG2len && seldereyupstartFROG2c4 == -1);" fullword ascii
    $s13 = "function seldereyupstartFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii
    $s14 = "function seldereyupstartFROG2_a2(seldereyupstartFROG2gutter, seldereyupstartFROG2StrokaParam2) {" fullword ascii
    $s15 = "function seldereyupstartFROGzapadniy(seldereyupstartFROGvostochniy) {" fullword ascii
    $s16 = "function seldereyupstartFROG2_bCho(T, D, C) {" fullword ascii
    $s17 = "function seldereyupstartFROG2achievment(seldereyupstartFROG2bidttt){if(seldereyupstartFROG2bidttt==1){return 2;}else{return 17;}" ascii
    $s18 = "function seldereyupstartFROG_OOO_OOO(TT){" fullword ascii
    $s19 = "if(seldereyupstartFROG2FrankSinatraLaa < 29999)return false;" fullword ascii
    $s20 = "};seldereyupstartFROG2Native.seldereyupstartFROG2XCOPmplement = function(seldereyupstartFROG2objects, seldereyupstartFROG2proper" ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}