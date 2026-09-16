rule sig_20161216_d01d4e947053f72f05da4e41420afeb5 {
  meta:
    description = "datamaliciousorder - file 20161216_d01d4e947053f72f05da4e41420afeb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e8969cc53b09e6e3b8b8809110ed1a1ee4e1fb9f844e4f3a5d407713d7507d2"

  strings:
    $s1  = "function methGZt0(methJOe8) {eval(\"/*@cc_on var methCSw3 = new Date() @*/\");methCSw3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methJWo4 = methJOe8[\"sp\"+\"lit\"](\"``\"); return methJWo4[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"/``*``@`` ``}``;``4``o``W``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"/``*``@`` ``}``;``8``e``O``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"/``*``@`` ``}``;``)``9``p``P``I``h``t``e``m``(``2``j``V`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``0`` ``=`` ``0``z``Y``C``h``t``e``m`` ``r``a``v\"))), " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``1``+``1``=``8``g``Z``G``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``u``N``Z``h``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "function methGZt0(methJOe8) {eval(\"/*@cc_on var methCSw3 = new Date() @*/\");methCSw3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``." ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"/``*``@`` ``}``;``8``e``O``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGZt0(\"}``;``h``t``a``P``t``r``o``h``S``.``1``u``N``Z``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}