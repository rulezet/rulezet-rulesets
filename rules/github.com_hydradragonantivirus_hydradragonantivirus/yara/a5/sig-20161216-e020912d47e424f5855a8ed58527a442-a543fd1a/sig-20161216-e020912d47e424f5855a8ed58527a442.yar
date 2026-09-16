rule sig_20161216_e020912d47e424f5855a8ed58527a442 {
  meta:
    description = "datamaliciousorder - file 20161216_e020912d47e424f5855a8ed58527a442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b6ee2fe4547a1c5601a5d5d3b999b32528e6ca456ac4da23130e2c219021efc"

  strings:
    $s1  = "function cheburgenDCk1(cheburgenMLh5) {eval(\"/*@cc_on var cheburgenWGp5 = new Date() @*/\");cheburgenWGp5[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``8``t``O``N``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``l``A``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``0``j``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``)``2``j``J``F``n``e``g``r``u``b``e``h" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``\\x22``e``w``o``b``h``/``m``o``c``.``8``6``o``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"}``;``h``t``a``P``t``r``o``h``S``.``8``w``I``n``e``g``r" ascii
    $s9  = "turn cheburgenNOt8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``8``t``O``N``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``c``B``Q``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``\\x22``i``7``l``h``0``n``h``/``m``o``c``.``z``i``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\"/``*``@`` ``}``;``)``2``j``J``F``n``e``g``r``u``b``e``h" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "function cheburgenDCk1(cheburgenMLh5) {eval(\"/*@cc_on var cheburgenWGp5 = new Date() @*/\");cheburgenWGp5[\"setUTC\"+\"Seconds" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``7``u``W``Z``n``e``g``r``u``b``e``h``c`` ``+`` ``3``v" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``\\x22``\\x22`` ``+`` ``1``c``Z``U``n``e``g``r``u`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDCk1(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}