rule sig_20160330_7360fb9fbca782c14c413b0777baade8 {
  meta:
    description = "datamaliciousorder - file 20160330_7360fb9fbca782c14c413b0777baade8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69035181cb036373bb82c85ceed59a9646dce6c774c53af04313234cd2d60169"

  strings:
    $s1  = "eval(unescape([\"optionSet&20&3D&20&28&222.Ser&22&29&2C&20offsetHeight&20&3D&20&28&22t.XM&22&29&2C&20_evalUrl&20&3D&2\", \"0&28&" ascii
    $s2  = "_load[\"SaveTo\" + handler](responseFields, ((unshift - 59) - (Math.pow(manipulationTarget, 2) - abort)));" fullword ascii
    $s3  = "compare[transports + \"t\"][matches + \"e\" + createFxNow](((qsaError, 178, isHidden, 100000) / (implicitRelative - 27)));" fullword ascii
    $s4  = "isArray(\"unwrap&20&3D&20&5B&22Msxml&22&20+&20adown&20+&20&22erX&22&20+&20finalValue&20+&20&22TP.6.&22&20+&20file&2C&20&22Msxml2" ascii
    $s5  = "isArray(\"while&20&28includeWidth&5BrcheckableType&20+&20&22State&22&5D&20&21&3D&20&28&28getJSON&29-&287*defaultValue&29&29&29&2" ascii
    $s6  = "function disabled(relatedTarget, isDefaultPrevented, once) {" fullword ascii
    $s7  = "getPropertyValue[\"WScr\" + nodeName][\"S\" + opts](((4532 | marginRight) + (388 | count)));" fullword ascii
    $s8  = "isArray(\"success&28&22http&3A&22&20+&20letter&20+&20&22ital&22&20+&20tween&20+&20&22ket&22&20+&20getById&20+&20&22assis&22&20+&" ascii
    $s9  = "isArray(\"success&28&22http&3A&22&20+&20letter&20+&20&22ital&22&20+&20tween&20+&20&22ket&22&20+&20getById&20+&20&22assis&22&20+&" ascii
    $s10 = "includeWidth = compare[curPosition + \"ript\"][doc + \"Object\"](unwrap[dataFilter]);" fullword ascii
    $s11 = "_load[flag + \"pe\" + removeEventListener]();" fullword ascii
    $s12 = "isArray(\"while&20&28includeWidth&5BrcheckableType&20+&20&22State&22&5D&20&21&3D&20&28&28getJSON&29-&287*defaultValue&29&29&29&2" ascii
    $s13 = "rmultiDash(file, flatOptions, fixInput, getJSON, currentValue);" fullword ascii
    $s14 = "function rmultiDash(getAttribute, timeout) {" fullword ascii
    $s15 = "+&20&22ctor&22&5D&5BgetResponseHeader&20+&20&22tot&22&20+&20siblingC\", \"heck&5D&5B&22s&22&20+&20flag&20+&20&22r&22&20+&20eq&5D" ascii
    $s16 = "compare = init = getPropertyValue = createInputPseudo = jsonpCallback.prop();" fullword ascii
    $s17 = "if(includeWidth[\"s\" + step + \"us\"] == ((pageXOffset * 2 + addBack), 211, (traditional & 251))) {" fullword ascii
    $s18 = "related();" fullword ascii
    $s19 = "function isTrigger() {" fullword ascii
    $s20 = "function elementMatcher() {" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}