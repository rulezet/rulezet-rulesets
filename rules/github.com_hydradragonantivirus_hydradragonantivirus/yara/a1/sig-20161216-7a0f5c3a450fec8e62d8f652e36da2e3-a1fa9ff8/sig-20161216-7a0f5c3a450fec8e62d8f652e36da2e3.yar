rule sig_20161216_7a0f5c3a450fec8e62d8f652e36da2e3 {
  meta:
    description = "datamaliciousorder - file 20161216_7a0f5c3a450fec8e62d8f652e36da2e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1006a101ebe4ddb977b2f61541fdeb838096a7256c7dd2631794ae3ff22af50"

  strings:
    $s1  = "function methSDf2(methZx6) {eval(\"/*@cc_on var methVl7 = new Date() @*/\");methVl7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"}``;``h``t``a``P``t``r``o``h``S``.``1``o``J``h``t``e``m`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"/``*``@`` ``}``;``6``x``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``m``O``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"/``*``@`` ``}``;``0``a``H``I``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"/``*``@`` ``}``;``6``x``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``3``i``S``h``t``e``m`` ``+`` ``4``j``O``H``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``1``+``1``=``5``w``R``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"/``*``@`` ``}``;``6``b``R``L``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"}``;``h``t``a``P``t``r``o``h``S``.``1``o``J``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\"/``*``@`` ``}``;``0``a``H``I``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSDf2(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}