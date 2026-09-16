rule sig_20161216_f081455be53e9fc71a0b882b988da015 {
  meta:
    description = "datamaliciousorder - file 20161216_f081455be53e9fc71a0b882b988da015.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4dab21b03b609e27ad371af49785ce31cd5873b277417f6619f58730f220f60"

  strings:
    $s1  = "function cheburgenLUp4(cheburgenBFg8) {eval(\"/*@cc_on var cheburgenUd8 = new Date() @*/\");cheburgenUd8[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "n cheburgenLOg6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"/``*``@`` ``}``;``)``1``d``W``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"/``*``@`` ``}``;``8``g``F``B``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``\\x22`` ``+`` ``5``q``O``n``e``g``r``u``b`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``2``p``D``A``n``e``g``r``u``b``e``h``c`` ``+`` ``7``p" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``0`` ``=`` ``6``a``K``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"/``*``@`` ``}``;``8``g``F``B``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``\\x22`` ``+`` ``5``q``O``n``e``g``r``u``b`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``1``+``1``=``5``x``X``N``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"/``*``@`` ``}``;``)``1``d``W``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``m``V``E``n" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLUp4(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}