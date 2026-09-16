rule sig_20161216_8d425dfcdb2a1d7d61ef1e187117cbc6 {
  meta:
    description = "datamaliciousorder - file 20161216_8d425dfcdb2a1d7d61ef1e187117cbc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d957ffacc267326d819e4440efe37de07bee6a3d8ef6bdefb4083431842e652"

  strings:
    $s1  = "function cheburgenVWj2(cheburgenPm7) {eval(\"/*@cc_on var cheburgenAOe4 = new Date() @*/\");cheburgenAOe4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``\\x22`` ``+`` ``7``v``X``T``n``e``g``r``u`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``0`` ``=`` ``3``u``N``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\"/``*``@`` ``}``;``4``v``O``B``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``h``C``V``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s11 = "function cheburgenVWj2(cheburgenPm7) {eval(\"/*@cc_on var cheburgenAOe4 = new Date() @*/\");cheburgenAOe4[\"setUTC\"+\"Seconds\"" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``k``V``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\"/``*``@`` ``}``;``)``5``m``A``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``1``+``1``=``4``o``X``B``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``0`` ``=`` ``3``u``N``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``p``D``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``p``D``n``e``g``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWj2(\";``)``\\x22``r``m``n``y``6``w``/``t``i``.``d``l``r``o``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}