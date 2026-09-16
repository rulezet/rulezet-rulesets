rule sig_20161216_811deab4f6972e37101fac2e4f9fe360 {
  meta:
    description = "datamaliciousorder - file 20161216_811deab4f6972e37101fac2e4f9fe360.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34b5f792b4be1508e8ba9705397d0f5c777dba947593ef87cb71521ac0ccde29"

  strings:
    $s1  = "function methJKl2(methFPw2) {eval(\"/*@cc_on var methEJf3 = new Date() @*/\");methEJf3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methLBp8 = methFPw2[\"sp\"+\"lit\"](\"``\"); return methLBp8[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``s``E``Y``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"}``;``h``t``a``P``t``r``o``h``S``.``4``i``T``L``h``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"/``*``@`` ``}``;``1``e``V``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s10 = "function methJKl2(methFPw2) {eval(\"/*@cc_on var methEJf3 = new Date() @*/\");methEJf3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"/``*``@`` ``}``;``)``9``g``H``C``h``t``e``m``(``1``v``V`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``0`` ``=`` ``8``z``M``P``h``t``e``m`` ``r``a``v\"))), " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``0`` ``=`` ``8``z``M``P``h``t``e``m`` ``r``a``v\"))), " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJKl2(\"/``*``@`` ``}``;``2``w``P``F``h``t``e``m`` ``n``r``u``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}