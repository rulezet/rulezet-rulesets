rule sig_20161216_6cdfd7edfabbc94b7d3db2a239f50b8a {
  meta:
    description = "datamaliciousorder - file 20161216_6cdfd7edfabbc94b7d3db2a239f50b8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58d757503c2fc0e10ed56b6f43c3b64b1403c18b0538d5a5d8abb5dfc317a6eb"

  strings:
    $s1  = "function methKw1(methNHh9) {eval(\"/*@cc_on var methPk4 = new Date() @*/\");methPk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "function methKw1(methNHh9) {eval(\"/*@cc_on var methPk4 = new Date() @*/\");methPk4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``)``9``k``C``W``h``t``e``m``(``4``s``V``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``5``e``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``1``w``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"}``;``h``t``a``P``t``r``o``h``S``.``6``t``N``h``t``e``m``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``1``+``1``=``0``u``Z``D``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``1``w``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``j``R``h``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``j``R``h``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKw1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}