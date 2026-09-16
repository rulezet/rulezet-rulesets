rule sig_20161215_999d3adaba936318adff3cdd0e24213e {
  meta:
    description = "datamaliciousorder - file 20161215_999d3adaba936318adff3cdd0e24213e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ac40a7bd85aaf38af84782bac26889cda03dae556826501542ffdb9e4f51069"

  strings:
    $s1  = "function cheburgenHm3(cheburgenLJi2) {eval(\"/*@cc_on var cheburgenFVb8 = new Date() @*/\");cheburgenFVb8[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"/``*``@`` ``}``;``8``z``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``8``b``E``O``n``e``g``r``u``b``e``h``c`` ``+`` ``7``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"/``*``@`` ``}``;``3``y``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``g``L``M`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``8``b``E``O``n``e``g``r``u``b``e``h``c`` ``+`` ``7``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``r``E``n``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``\\x22``d``o``9``u``h``q``s``f``3``a``/``w``z``.``g" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"/``*``@`` ``}``;``2``i``J``L``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``1``+``1``=``9``g``K``T``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "function cheburgenHm3(cheburgenLJi2) {eval(\"/*@cc_on var cheburgenFVb8 = new Date() @*/\");cheburgenFVb8[\"setUTC\"+\"Seconds\"" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHm3(\";``1``+``1``=``9``g``K``T``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}