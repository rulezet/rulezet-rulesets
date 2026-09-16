rule sig_20161216_4e284828e94974427852bab5a200bdc1 {
  meta:
    description = "datamaliciousorder - file 20161216_4e284828e94974427852bab5a200bdc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37b2be23a6d2d4be4398b34bca420953d8ad71c91e9e73fcdd59b31dcf30aedb"

  strings:
    $s1  = "function cheburgenPUg6(cheburgenUq4) {eval(\"/*@cc_on var cheburgenKBr9 = new Date() @*/\");cheburgenKBr9[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``\\x22``\\x22`` ``+`` ``5``l``S``n``e``g``r``u``b`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``1``+``1``=``0``l``J``Q``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"/``*``@`` ``}``;``)``9``j``E``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"/``*``@`` ``}``;``4``q``U``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "function cheburgenPUg6(cheburgenUq4) {eval(\"/*@cc_on var cheburgenKBr9 = new Date() @*/\");cheburgenKBr9[\"setUTC\"+\"Seconds\"" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``n``L``W" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"/``*``@`` ``}``;``7``z``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\"}``;``h``t``a``P``t``r``o``h``S``.``3``m``O``n``e``g``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``0`` ``=`` ``7``l``X``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "rn cheburgenSBd0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPUg6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``n``L``W" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}