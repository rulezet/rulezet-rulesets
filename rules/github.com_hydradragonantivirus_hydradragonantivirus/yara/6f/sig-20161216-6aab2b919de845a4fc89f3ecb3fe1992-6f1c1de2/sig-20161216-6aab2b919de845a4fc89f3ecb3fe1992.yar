rule sig_20161216_6aab2b919de845a4fc89f3ecb3fe1992 {
  meta:
    description = "datamaliciousorder - file 20161216_6aab2b919de845a4fc89f3ecb3fe1992.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d84cd8094cbac334aaaebd1669642abe75fbffcb7d3b6833dbc084b1fd62ac9"

  strings:
    $s1  = "function methQa5(methXUz5) {eval(\"/*@cc_on var methUv6 = new Date() @*/\");methUv6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"/``*``@`` ``}``;``3``b``Z``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"}``;``h``t``a``P``t``r``o``h``S``.``6``d``U``h``t``e``m``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``t``R``N``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``1``r``K``h``t``e``m`` ``+`` ``2``c``C``h``t``e``m``=``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"/``*``@`` ``}``;``5``z``U``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "function methQa5(methXUz5) {eval(\"/*@cc_on var methUv6 = new Date() @*/\");methUv6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"/``*``@`` ``}``;``5``z``U``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"/``*``@`` ``}``;``)``8``y``M``h``t``e``m``(``8``y``T``Q``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``1``r``K``h``t``e``m`` ``+`` ``2``c``C``h``t``e``m``=``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIRl9 = methXUz5[\"sp\"+\"lit\"](\"``\"); return methIRl9[\"reverse\"" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``1``+``1``=``5``j``V``J``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\"}``;``h``t``a``P``t``r``o``h``S``.``6``d``U``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQa5(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}