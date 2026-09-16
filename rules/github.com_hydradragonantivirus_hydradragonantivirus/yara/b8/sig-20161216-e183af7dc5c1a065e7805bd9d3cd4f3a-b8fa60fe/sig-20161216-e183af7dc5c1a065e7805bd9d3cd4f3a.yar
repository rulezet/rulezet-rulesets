rule sig_20161216_e183af7dc5c1a065e7805bd9d3cd4f3a {
  meta:
    description = "datamaliciousorder - file 20161216_e183af7dc5c1a065e7805bd9d3cd4f3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f388c25341de8d4f9b79d2ebaa9fe29075ce29ff40fc35fb780d93cb6bfc1a11"

  strings:
    $s1  = "function methHCk8(methBOi8) {eval(\"/*@cc_on var methBDf6 = new Date() @*/\");methBDf6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methQt2 = methBOi8[\"sp\"+\"lit\"](\"``\"); return methQt2[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``2``t``Q``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``m``Y``S``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``0`` ``=`` ``4``j``E``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s6  = "function methHCk8(methBOi8) {eval(\"/*@cc_on var methBDf6 = new Date() @*/\");methBDf6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``x``D``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``m``Y``S``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``0`` ``=`` ``4``j``E``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``2``t``Q``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"/``*``@`` ``}``;``)``5``q``L``M``h``t``e``m``(``2``k``H`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHCk8(\"}``;``h``t``a``P``t``r``o``h``S``.``3``a``M``B``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}