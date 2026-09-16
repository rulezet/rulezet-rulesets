rule sig_20161216_8680cfaeabf67d7578475a849cf4690c {
  meta:
    description = "datamaliciousorder - file 20161216_8680cfaeabf67d7578475a849cf4690c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7134fafdf880472c56539f0fff83a83704ed346aef15a0231b9541446e63881b"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZk9 = methWx4[\"sp\"+\"lit\"](\"``\"); return methZk9[\"reverse" ascii
    $s2  = "function methCAy6(methWx4) {eval(\"/*@cc_on var methMWs6 = new Date() @*/\");methMWs6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``0`` ``=`` ``0``x``C``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"}``;``h``t``a``P``t``r``o``h``S``.``5``m``P``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"/``*``@`` ``}``;``9``k``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"/``*``@`` ``}``;``1``i``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"/``*``@`` ``}``;``4``x``W``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``9``p``G``O``h``t``e``m`` ``+`` ``5``l``Q``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``1``+``1``=``8``s``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\"/``*``@`` ``}``;``1``i``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCAy6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``u``W``Y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}