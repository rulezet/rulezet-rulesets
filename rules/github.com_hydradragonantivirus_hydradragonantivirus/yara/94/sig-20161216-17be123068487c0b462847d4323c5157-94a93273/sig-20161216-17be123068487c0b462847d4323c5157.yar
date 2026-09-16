rule sig_20161216_17be123068487c0b462847d4323c5157 {
  meta:
    description = "datamaliciousorder - file 20161216_17be123068487c0b462847d4323c5157.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3e1de426d32b3049a02936bd88cad29a3d36bbf9dd46c50b57eb86429233c8e"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOZv9 = methNw3[\"sp\"+\"lit\"](\"``\"); return methOZv9[\"reverse" ascii
    $s2  = "function methZu8(methNw3) {eval(\"/*@cc_on var methFAg2 = new Date() @*/\");methFAg2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``0`` ``=`` ``1``y``O``Z``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"/``*``@`` ``}``;``9``v``Z``O``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"}``;``h``t``a``P``t``r``o``h``S``.``8``y``R``P``h``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``i``C``X``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"/``*``@`` ``}``;``3``w``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``t``L``U``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"/``*``@`` ``}``;``3``w``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``1``+``1``=``7``x``V``K``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZu8(\";``1``+``1``=``7``x``V``K``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}