rule sig_20161215_881c2e963d934c1afef484906fa4ad6c {
  meta:
    description = "datamaliciousorder - file 20161215_881c2e963d934c1afef484906fa4ad6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e4c5e29bc5072ccafff79b19ea0836ce027ac3ed28cb2f1c3321e8096355c3f"

  strings:
    $s1  = "function cheburgenTc6(cheburgenCVw4) {eval(\"/*@cc_on var cheburgenMz8 = new Date() @*/\");cheburgenMz8[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenMz8[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenJe2 = cheburgenCVw4[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``\\x22`` ``+`` ``2``b``P``n``e``g``r``u``b``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"/``*``@`` ``}``;``4``w``V``C``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"/``*``@`` ``}``;``)``1``l``O``P``n``e``g``r``u``b``e``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``x``L``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``)``\\x22``\\x22`` ``+`` ``2``b``P``n``e``g``r``u``b``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\";``7``o``N``P``n``e``g``r``u``b``e``h``c`` ``+`` ``8``q`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"/``*``@`` ``}``;``4``w``V``C``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"}``;``h``t``a``P``t``r``o``h``S``.``6``m``F``n``e``g``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTc6(\"/``*``@`` ``}``;``1``k``T``Z``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}