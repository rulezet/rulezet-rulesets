rule sig_20161216_1793508e3739281548aaa49ebf15720a {
  meta:
    description = "datamaliciousorder - file 20161216_1793508e3739281548aaa49ebf15720a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea3f6c558f90afa67b028f0a36d46044865f98a65b72160ad549e7acf6521203"

  strings:
    $s1  = "function methKHp2(methMl0) {eval(\"/*@cc_on var methJd1 = new Date() @*/\");methJd1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"/``*``@`` ``}``;``)``1``j``L``h``t``e``m``(``4``t``N``F`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``0`` ``=`` ``0``s``V``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s8  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSTf0 = methMl0[\"sp\"+\"lit\"](\"``\"); return methSTf0[\"reverse\"]" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``h``X``X``h``t``e`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``j``C``I`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``1``+``1``=``1``o``U``K``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"/``*``@`` ``}``;``0``b``R``E``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``0`` ``=`` ``0``s``V``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\"/``*``@`` ``}``;``0``l``M``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKHp2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}