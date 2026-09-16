rule sig_20161215_5631091f68512e9e57f33505b8b5ddcc {
  meta:
    description = "datamaliciousorder - file 20161215_5631091f68512e9e57f33505b8b5ddcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "561b82a49eb1fdf8f469dd63c36bb5124c5ad9a47e5b8636ef849415a61a5a20"

  strings:
    $s1  = "0\");if (cheburgenKi1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenIFi8 = cheburgenLj9[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenMp5(cheburgenLj9) {eval(\"/*@cc_on var cheburgenKi1 = new Date() @*/\");cheburgenKi1[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``z``L``n``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"\")), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``9``j``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``0`` ``=`` ``5``d``H``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``g" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``r``O``V`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``8``f``Z``S``n``e``g``r``u``b``e``h``c`` ``+`` ``9``o`" ascii
    $s12 = "heburgenIFi8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``)``\\x22``\\x22`` ``+`` ``6``l``W``W``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``4``w``X``Q``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``)``5``t``M``Z``n``e``g``r``u``b``e``h`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "function cheburgenMp5(cheburgenLj9) {eval(\"/*@cc_on var cheburgenKi1 = new Date() @*/\");cheburgenKi1[\"setUTC\"+\"Seconds\"](" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMp5(\"/``*``@`` ``}``;``8``i``F``I``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}