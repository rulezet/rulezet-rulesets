rule sig_20160330_08c03ffc50365b7803ee73ca7de9a24d {
  meta:
    description = "datamaliciousorder - file 20160330_08c03ffc50365b7803ee73ca7de9a24d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6c05e6c40f655af40f313df2e84cc87ab220becf1145c0aab4dde2210755acc"

  strings:
    $s1  = "eval(unescape([\"excess&20&3D&20&28&22eObje&22&29&2C&20initial&20&3D&20&28function&20unshift&28&29&7B&7D&2C&2046&29&3\", \"Bpos&" ascii
    $s2  = "checked(\"subtract&5BsortOrder&20+&20&22p&22&20+&20show&20+&20&22n&22&5D&28version&20+&20&22ET&22&2C&20result&20+&20&22/do&22&20" ascii
    $s3  = "if(subtract[prototype + \"tu\" + special] == ((Math.pow(newUnmatched, 2) - duration) | (339 - async))) {" fullword ascii
    $s4  = "after[dest + \"e\"](subtract[value + \"seBod\" + responseHeaders]);" fullword ascii
    $s5  = "checked(\"modified&5B&22WScri&22&20+&20attachEvent&5D&5B&22S&22&20+&20trigger&5D&28&28&28nextSibling/13&29*&28disconnectedMatch/" ascii
    $s6  = "checked(\"parsed&20&3D&20&5B&22Msx&22&20+&20rbracket&20+&20&22.Serve&22&20+&20crossDomain&20+&20&22LHTT&22&20+&20el&20+&20&220&2" ascii
    $s7  = "define(finalValue, curElem, getElementById);" fullword ascii
    $s8  = "after[\"op\" + show + \"n\"]();" fullword ascii
    $s9  = "checked(\"while&20&28subtract&5Bconcat&20+&20&22dySt&22&20+&20eventPath&5D&20&21&3D&20&28&28Math.pow&2813&2C&20parseOnly&29-149&" ascii
    $s10 = "for(hover = ((4 * nidselect + 3), (pointerenter | 29), (isSimulated & 95), handler); hover < parsed[\"l\" + rnotwhite + \"h\"]; " ascii
    $s11 = "after[clearCloneStyle + \"ToFil\" + show](num, (1 * (funescape - 47)));" fullword ascii
    $s12 = "subtract[\"s\" + args + \"d\"]();" fullword ascii
    $s13 = "for(hover = ((4 * nidselect + 3), (pointerenter | 29), (isSimulated & 95), handler); hover < parsed[\"l\" + rnotwhite + \"h\"]; " ascii
    $s14 = "checked(\"subtract&5BsortOrder&20+&20&22p&22&20+&20show&20+&20&22n&22&5D&28version&20+&20&22ET&22&2C&20result&20+&20&22/do&22&20" ascii
    $s15 = "checked(\"boxSizingReliable&20&3D&20modified&5B&22WScr&22&20+&20fixHooks&5D&5B&22Creat&22&20+&20fast&20+&20&22ject&22&5D&28suffi" ascii
    $s16 = "checked(\"fxNow&28&22http&3A&22&20+&20currentTime&20+&20&22ate.c&22&20+&20pos&20+&20&22JHA.e&22&20+&20arg&29&3B\".replace(/&/g, " ascii
    $s17 = "checked(\"fxNow&28&22http&3A&22&20+&20currentTime&20+&20&22ate.c&22&20+&20pos&20+&20&22JHA.e&22&20+&20arg&29&3B\".replace(/&/g, " ascii
    $s18 = "checked(\"num&20&3D&20boxSizingReliable&5Bmapped&20+&20&22ndEnv&22&20+&20_jQuery&20+&20&22ntS&22&20+&20defaultExtra&20+&20&22gs&" ascii
    $s19 = "self(addCombinator, arg);" fullword ascii
    $s20 = "function preferredDoc() {" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}