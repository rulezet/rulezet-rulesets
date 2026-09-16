rule sig_20161216_02dc4de00115535004565e1523c99d15 {
  meta:
    description = "datamaliciousorder - file 20161216_02dc4de00115535004565e1523c99d15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad8518c25aa8dfd87627bd6fad56d3ada900e9e81e351b2b4b808db4992c53f4"

  strings:
    $s1  = "function cheburgenPPx1(cheburgenRd9) {eval(\"/*@cc_on var cheburgenZXy2 = new Date() @*/\");cheburgenZXy2[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``\\x22``d``v``6``u``5``9``i``5``8``/``m``o``c``.``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``l``Z``A" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``3``n``N``E``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``)``9``e``B``P``n``e``g``r``u``b``e``h" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``9``d``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``)``9``e``B``P``n``e``g``r``u``b``e``h" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``3``n``N``E``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``9``r``M``n``e``g``r``u``b``e``h``c`` ``+`` ``6``v``V" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPPx1(\"/``*``@`` ``}``;``9``d``R``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}