rule sig_20161216_493d5a9b983432dbc502f3185c6e300a {
  meta:
    description = "datamaliciousorder - file 20161216_493d5a9b983432dbc502f3185c6e300a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90179b8c8f641ee94db48308e78b3b05a9a58ef2bbf209ae35f2724ab5fce123"

  strings:
    $s1  = "function methPg5(methTPb4) {eval(\"/*@cc_on var methXp8 = new Date() @*/\");methXp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``4``r``J``F``h``t``e``m`` ``+`` ``1``y``I``G``h``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``e``G``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``e``G``h``" ascii
    $s7  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYl5 = methTPb4[\"sp\"+\"lit\"](\"``\"); return methYl5[\"reverse\"](" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\"/``*``@`` ``}``;``3``y``I``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii
    $s13 = "function methPg5(methTPb4) {eval(\"/*@cc_on var methXp8 = new Date() @*/\");methXp8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\"/``*``@`` ``}``;``4``b``P``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``0`` ``=`` ``7``a``A``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``a``A``E``h``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPg5(\"/``*``@`` ``}``;``3``y``I``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}