rule sig_20161216_405191fe29598abaa48a3119c2a0ec34 {
  meta:
    description = "datamaliciousorder - file 20161216_405191fe29598abaa48a3119c2a0ec34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0302ce3d1213eb3079c650243e056398f8906ade897ebec8aa4d7865fc032124"

  strings:
    $s1  = "function cheburgenNm5(cheburgenPUp1) {eval(\"/*@cc_on var cheburgenCRx2 = new Date() @*/\");cheburgenCRx2[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``w``X``n``e`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``w``X``n``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``1``p``U``P``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"\")), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``0`` ``=`` ``5``e``Y``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``7``f``N``N``n``e``g``r``u``b``e``h``c`` ``+`` ``6``x`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``)``\\x22``\\x22`` ``+`` ``4``e``H``n``e``g``r``u``b``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``2``w``W``A``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``)``\\x22``\\x22`` ``+`` ``4``e``H``n``e``g``r``u``b``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``2``w``W``A``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\"/``*``@`` ``}``;``7``s``F``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNm5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}