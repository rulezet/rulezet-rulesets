rule sig_20161216_530b2447acc8c7d353334f3d135e24f8 {
  meta:
    description = "datamaliciousorder - file 20161216_530b2447acc8c7d353334f3d135e24f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9cda14bfa901c40c56fad860fd4e1b7a92881980de8950db48f7489397b0326"

  strings:
    $s1  = "function cheburgenDy1(cheburgenIVn1) {eval(\"/*@cc_on var cheburgenUt4 = new Date() @*/\");cheburgenUt4[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenUt4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenJa8 = cheburgenIVn1[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``t" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\"}``;``h``t``a``P``t``r``o``h``S``.``2``x``L``n``e``g``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``5``d``F``n``e``g``r``u``b``e``h``c`` ``+`` ``3``t``R`" ascii
    $s8  = "function cheburgenDy1(cheburgenIVn1) {eval(\"/*@cc_on var cheburgenUt4 = new Date() @*/\");cheburgenUt4[\"setUTC\"+\"Seconds\"](" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``y``R``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``0`` ``=`` ``0``b``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\"/``*``@`` ``}``;``4``q``W``J``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\"/``*``@`` ``}``;``1``n``V``I``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\"/``*``@`` ``}``;``)``8``a``L``I``n``e``g``r``u``b``e``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDy1(\";``1``+``1``=``5``o``Q``B``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}