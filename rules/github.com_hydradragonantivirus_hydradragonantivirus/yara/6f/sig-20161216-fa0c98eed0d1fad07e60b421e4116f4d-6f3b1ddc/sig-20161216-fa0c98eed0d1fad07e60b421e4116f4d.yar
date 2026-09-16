rule sig_20161216_fa0c98eed0d1fad07e60b421e4116f4d {
  meta:
    description = "datamaliciousorder - file 20161216_fa0c98eed0d1fad07e60b421e4116f4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8706100b1c6c5d52c8ebd6cbc5aca0f4e63e51b6f4349d3b279c02d233678014"

  strings:
    $s1  = "function cheburgenYm2(cheburgenYKn7) {eval(\"/*@cc_on var cheburgenTEu7 = new Date() @*/\");cheburgenTEu7[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``0`` ``=`` ``2``a``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``\\x22``\\x22`` ``+`` ``5``r``X``I``n``e``g``r``u``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``0`` ``=`` ``2``a``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``1``+``1``=``3``d``Z``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"/``*``@`` ``}``;``1``j``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``5``w``V``W``n``e``g``r``u``b``e``h``c`` ``+`` ``1``x`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``\\x22``\\x22`` ``+`` ``5``r``X``I``n``e``g``r``u``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"/``*``@`` ``}``;``7``u``W``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"/``*``@`` ``}``;``1``j``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``u``B``C`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"/``*``@`` ``}``;``7``n``K``Y``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYm2(\";``5``w``V``W``n``e``g``r``u``b``e``h``c`` ``+`` ``1``x`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}