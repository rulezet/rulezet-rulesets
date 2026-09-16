rule sig_20161216_90c828ba5e1c98832629d03f43157ad4 {
  meta:
    description = "datamaliciousorder - file 20161216_90c828ba5e1c98832629d03f43157ad4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "092c9d4c7f0df8f473c215b6549e4a7766c3e489b81bca8f9071df9fd514f724"

  strings:
    $s1  = "function cheburgenEVj4(cheburgenAEq3) {eval(\"/*@cc_on var cheburgenEMo8 = new Date() @*/\");cheburgenEMo8[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``n``S``n" ascii
    $s3  = "turn cheburgenPZv8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"/``*``@`` ``}``;``3``q``E``A``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``9``n``K``J``n``e``g``r``u``b``e``h``c`` ``+`` ``0``t" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``\\x22``9``c``t``y``d``q``4``/``m``o``c``.``a``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"/``*``@`` ``}``;``)``2``o``F``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"/``*``@`` ``}``;``7``t``Z``S``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "function cheburgenEVj4(cheburgenAEq3) {eval(\"/*@cc_on var cheburgenEMo8 = new Date() @*/\");cheburgenEMo8[\"setUTC\"+\"Seconds" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``z``H``Q``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``\\x22``5``n``q``p``t``c``b``e``r``7``/``e``d``.``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``\\x22``\\x22`` ``+`` ``1``s``B``O``n``e``g``r``u`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\";``)``\\x22``\\x22`` ``+`` ``1``s``B``O``n``e``g``r``u`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEVj4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}