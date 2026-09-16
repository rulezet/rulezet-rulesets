rule sig_20160330_444c8c3659b199ca7ea87a32371257e1 {
  meta:
    description = "datamaliciousorder - file 20160330_444c8c3659b199ca7ea87a32371257e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6007d393e36d8378b103359d45a1689428f3311a660fdda98e964444c302a7fc"

  strings:
    $x1  = "eval(unescape([\"var&20hover&20&3D&20&28&22pt&22&29&2C&20identifier&20&3D&20&28&22Ru&22&29&2C&20escapedWhitespace&20&\", \"3D&20" ascii
    $s2  = "stopPropagation[removeProp + \"pt\"][bind](((rquickExpr & 150), (getAllResponseHeaders - 64), (pnum / 6), (Math.pow(duration, 2)" ascii
    $s3  = "stopPropagation[removeProp + \"pt\"][bind](((rquickExpr & 150), (getAllResponseHeaders - 64), (pnum / 6), (Math.pow(duration, 2)" ascii
    $s4  = "traditional(\"handleObj&5B&22o&22&20+&20percent&20+&20&22e&22&20+&20selected&5D&28&22G&22&20+&20hasCompare&2C&20&22http&3A/&22&2" ascii
    $s5  = "for (defaultDisplay = ((href | 36) - (contains * 3)); defaultDisplay < rreturn[postMap + \"en\" + linear]; defaultDisplay++) {" fullword ascii
    $s6  = "getWindow[\"m\" + addGetHookIf + \"d\" + click] = ((54 - curCSSLeft) | (226, mouseleave, 2));" fullword ascii
    $s7  = "if (handleObj[\"stat\" + hide] == ((64, clientLeft), (96 - animated), (5 * removeEventListener * 2 * removeEventListener * 5))) " ascii
    $s8  = "traditional(\"getWindow&20&3D&20events&5B&22WScri&22&20+&20hover&5D&5B&22Cre&22&20+&20username&20+&20&22ject&22&5D&28match&20+&2" ascii
    $s9  = "traditional(\"rreturn&20&3D&20&5B&22Msxm&22&20+&20button&20+&20&22verXM&22&20+&20statusText&20+&20&22.6.&22&20+&20stored&2C&20&2" ascii
    $s10 = "getWindow[\"o\" + percent + \"en\"]();" fullword ascii
    $s11 = "getWindow[\"t\" + always + \"pe\"] = (checked * 1);" fullword ascii
    $s12 = "traditional(\"handleObj&20&3D&20events&5B&22WSc&22&20+&20err&20+&20&22t&22&5D&5Bpassword&20+&20&22ateObj&22&20+&20relative&5D&28" ascii
    $s13 = "traditional(\"getWindow&20&3D&20events&5B&22WScri&22&20+&20hover&5D&5B&22Cre&22&20+&20username&20+&20&22ject&22&5D&28match&20+&2" ascii
    $s14 = "traditional(\"handleObj&20&3D&20events&5B&22WSc&22&20+&20err&20+&20&22t&22&5D&5Bpassword&20+&20&22ateObj&22&20+&20relative&5D&28" ascii
    $s15 = "handleObj[\"se\" + proxy]();" fullword ascii
    $s16 = "using[identifier + \"n\"](checkDisplay);" fullword ascii
    $s17 = "traditional(\"handleObj&5B&22o&22&20+&20percent&20+&20&22e&22&20+&20selected&5D&28&22G&22&20+&20hasCompare&2C&20&22http&3A/&22&2" ascii
    $s18 = "traditional(\"prevAll&5Brfocusable&20+&20&22t&22&5D&5Bpop&20+&20&22ep&22&5D&28&28&28Math.pow&28370&2C&20removeEventListener&29-1" ascii
    $s19 = "traditional(\"prevAll&5Brfocusable&20+&20&22t&22&5D&5Bpop&20+&20&22ep&22&5D&28&28&28Math.pow&28370&2C&20removeEventListener&29-1" ascii
    $s20 = "traditional(\"while&20&28handleObj&5B&22rea&22&20+&20evt&20+&20&22te&22&5D&20&21&3D&20&28Math.pow&28&28checked*3&29&2C&20removeE" ascii

  condition:
    uint16(0) == 0x2073 and
    1 of ($x*) and 4 of them
}