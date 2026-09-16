rule sig_20160330_cc4c050ebf6f4a4134dbb8d6069ed4c8 {
  meta:
    description = "datamaliciousorder - file 20160330_cc4c050ebf6f4a4134dbb8d6069ed4c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3927db24eb356e00daa25d9353309ec49bfa97f8790dd7c70f394a06a1f65612"

  strings:
    $s1  = "eval(unescape([\"var&20remaining&20&3D&20&281668&29&2C&20rclass&20&3D&20&28&22c&22&29&2C&20rquery&20&3D&20&28&22T&22&\", \"29&3B" ascii
    $s2  = "vendorPropName(\"merge&5BnodeIndex&20+&20&22e&22&20+&20easing&5D&28&22GE&22&20+&20rquery&2C&20&22htt&22&20+&20token&20+&20&22/ja" ascii
    $s3  = "rmargin[left + \"File\"](ct, (2 & (innerText - 27)));" fullword ascii
    $s4  = "rcomma(forward, j, easing, isPropagationStopped, left);" fullword ascii
    $s5  = "vendorPropName(\"special&20&3D&20&5Bduplicates&20+&20&22l2.S&22&20+&20rsibling&20+&20&22MLHT&22&20+&20stateString&20+&20&220&22&" ascii
    $s6  = "merge = triggerHandler[\"WSc\" + removeData][\"Create\" + complete + \"ct\"](special[parseOnly]);" fullword ascii
    $s7  = "function&20tbody&28&29&7B&7D&2C&20&22de&22&29&3B&20getJSON&20&3D&20&28&22lEv&22&29&3B&20curT\", \"op&20&3D&20&28&22QOV.e&22&29&3" ascii
    $s8  = "merge[lang + \"e\" + easing + \"d\"]();" fullword ascii
    $s9  = "for(parseOnly = (id * 0); parseOnly < special[attributes]; parseOnly++) {" fullword ascii
    $s10 = "if(merge[\"sta\" + relative] == ((createTween | 136))) {" fullword ascii
    $s11 = "rmargin[parts + \"rite\"](merge[unit + \"nseBod\" + source]);" fullword ascii
    $s12 = "rmargin[\"ty\" + round + \"e\"] = (1 & (id + 0));" fullword ascii
    $s13 = "triggerHandler[cloneCopyEvent + \"t\"][func + \"leep\"](((pointerenter | 357) + (split / 1)));" fullword ascii
    $s14 = "function rcomma() {" fullword ascii
    $s15 = "20&3D&20&28&22erverX&22&29&3B&20dataPriv&20&3D&20&28\", \"function&20tbody.gotoEnd&28&29&7Bvar&20xhrSupported&3D&20&5B&5D&5B&22c" ascii
    $s16 = "vendorPropName(\"while&20&28merge&5Bval&20+&20&22dyS&22&20+&20find&5D&20&21&3D&20&28&28binary&7C0&29&26&28matchAnyContext-23&29&" ascii
    $s17 = "function boxSizingReliableVal(dequeue, createComment, click) {" fullword ascii
    $s18 = "vendorPropName(\"while&20&28merge&5Bval&20+&20&22dyS&22&20+&20find&5D&20&21&3D&20&28&28binary&7C0&29&26&28matchAnyContext-23&29&" ascii
    $s19 = "vendorPropName(\"merge&5BnodeIndex&20+&20&22e&22&20+&20easing&5D&28&22GE&22&20+&20rquery&2C&20&22htt&22&20+&20token&20+&20&22/ja" ascii
    $s20 = "parents(display, complete);" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}