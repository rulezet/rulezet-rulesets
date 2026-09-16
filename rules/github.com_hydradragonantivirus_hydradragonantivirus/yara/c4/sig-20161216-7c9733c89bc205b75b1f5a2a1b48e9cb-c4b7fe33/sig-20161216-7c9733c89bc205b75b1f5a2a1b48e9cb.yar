rule sig_20161216_7c9733c89bc205b75b1f5a2a1b48e9cb {
  meta:
    description = "datamaliciousorder - file 20161216_7c9733c89bc205b75b1f5a2a1b48e9cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e08042f6d568430ed2fdc6bfd868cf277c7380f9caa76e5df214369135dd93"

  strings:
    $s1  = "function methJNa4(methXNp6) {eval(\"/*@cc_on var methNy4 = new Date() @*/\");methNy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``1``x``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``d``C``V``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``j``S``R``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``2``s``M``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``7``o``F``S``h``t``e``m`` ``+`` ``5``x``I``h``t``e``m`" ascii
    $s9  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methHx1 = methXNp6[\"sp\"+\"lit\"](\"``\"); return methHx1[\"reverse\"]" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"/``*``@`` ``}``;``)``0``p``S``X``h``t``e``m``(``5``d``H`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``0`` ``=`` ``8``x``Z``R``h``t``e``m`` ``r``a``v\"))), " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``r``U``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``7``o``F``S``h``t``e``m`` ``+`` ``5``x``I``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJNa4(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}