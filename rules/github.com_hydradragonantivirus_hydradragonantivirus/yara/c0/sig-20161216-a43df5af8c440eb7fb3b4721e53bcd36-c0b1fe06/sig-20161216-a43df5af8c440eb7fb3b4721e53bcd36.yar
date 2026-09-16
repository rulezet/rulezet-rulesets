rule sig_20161216_a43df5af8c440eb7fb3b4721e53bcd36 {
  meta:
    description = "datamaliciousorder - file 20161216_a43df5af8c440eb7fb3b4721e53bcd36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fb06ed9e3f8be08d476c6a383e5cff24fb673c2f8f79545e233a56e8ad139fd"

  strings:
    $s1  = "function methFGm4(methHu8) {eval(\"/*@cc_on var methZq7 = new Date() @*/\");methZq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"/``*``@`` ``}``;``8``u``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``1``+``1``=``0``j``A``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"/``*``@`` ``}``;``)``3``s``U``h``t``e``m``(``6``m``U``K`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``9``l``L``h``t``e``m`` ``+`` ``9``s``A``G``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``m``Z``J``h``t``e`" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOa7 = methHu8[\"sp\"+\"lit\"](\"``\"); return methOa7[\"reverse\"]()" ascii
    $s14 = "function methFGm4(methHu8) {eval(\"/*@cc_on var methZq7 = new Date() @*/\");methZq7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"/``*``@`` ``}``;``7``a``O``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\"/``*``@`` ``}``;``)``3``s``U``h``t``e``m``(``6``m``U``K`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFGm4(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}