rule sig_20161216_7abc16900aa45b35480c348915029c5b {
  meta:
    description = "datamaliciousorder - file 20161216_7abc16900aa45b35480c348915029c5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797b2c7edc1d330ee7e7ffbf366acd2674b7a0b50d4f66956b6b4889d6a4f538"

  strings:
    $s1  = "function cheburgenLIf3(cheburgenAUu4) {eval(\"/*@cc_on var cheburgenSUi3 = new Date() @*/\");cheburgenSUi3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``y``b``6``g``h``i``9``/``m``o``c``.``n``g``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``d``v``6``u``5``9``i``5``8``/``m``o``c``.``" ascii
    $s5  = "turn cheburgenSJd8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``1``+``1``=``4``j``W``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\"/``*``@`` ``}``;``8``d``J``S``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``y``b``6``g``h``i``9``/``m``o``c``.``n``g``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``3``o``S``S``n``e``g``r``u``b``e``h``c`` ``+`` ``5``r" ascii
    $s12 = "function cheburgenLIf3(cheburgenAUu4) {eval(\"/*@cc_on var cheburgenSUi3 = new Date() @*/\");cheburgenSUi3[\"setUTC\"+\"Seconds" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``3``o``S``S``n``e``g``r``u``b``e``h``c`` ``+`` ``5``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``s``F``N``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\"/``*``@`` ``}``;``4``u``U``A``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``\\x22`` ``+`` ``9``x``O``A``n``e``g``r``u`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``)``\\x22``d``l``d``s``v``9``/``m``o``c``.``g``n``u``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLIf3(\";``0`` ``=`` ``6``q``D``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}