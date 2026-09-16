rule sig_20161216_94d496b39cb5799f6aae5f3784e9f067 {
  meta:
    description = "datamaliciousorder - file 20161216_94d496b39cb5799f6aae5f3784e9f067.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92e7f3c0f8b3dc178b2b381fa9337d03dbb36e2288ba6f303ab3c68d27a81a1e"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methLMz7 = methTAx2[\"sp\"+\"lit\"](\"``\"); return methLMz7[\"rever" ascii
    $s2  = "function methPd6(methTAx2) {eval(\"/*@cc_on var methYEb9 = new Date() @*/\");methYEb9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"/``*``@`` ``}``;``7``z``M``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"/``*``@`` ``}``;``7``z``M``L``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``E``h``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"}``;``h``t``a``P``t``r``o``h``S``.``2``k``M``Z``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"/``*``@`` ``}``;``)``2``z``L``T``h``t``e``m``(``3``c``E``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"/``*``@`` ``}``;``2``x``A``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"}``;``h``t``a``P``t``r``o``h``S``.``2``k``M``Z``h``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\"/``*``@`` ``}``;``1``u``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPd6(\";``3``t``C``A``h``t``e``m`` ``+`` ``7``a``P``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}