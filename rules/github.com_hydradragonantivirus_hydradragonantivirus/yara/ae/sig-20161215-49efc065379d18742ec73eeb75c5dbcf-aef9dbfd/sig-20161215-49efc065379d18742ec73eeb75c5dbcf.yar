rule sig_20161215_49efc065379d18742ec73eeb75c5dbcf {
  meta:
    description = "datamaliciousorder - file 20161215_49efc065379d18742ec73eeb75c5dbcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3bb5b7d94f667410017561a2c8acad2fe3f25e83ca45ce7cd0727b675f01bfa"

  strings:
    $s1  = "function cheburgenXFq1(cheburgenZKx2) {eval(\"/*@cc_on var cheburgenRFg4 = new Date() @*/\");cheburgenRFg4[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``0`` ``=`` ``6``t``X``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"/``*``@`` ``}``;``2``x``K``Z``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``6``i``B``E``n``e``g``r``u``b``e``h``c`` ``+`` ``9``j" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"}``;``h``t``a``P``t``r``o``h``S``.``6``v``B``n``e``g``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``6``i``B``E``n``e``g``r``u``b``e``h``c`` ``+`` ``9``j" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``m``O``L``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s14 = "function cheburgenXFq1(cheburgenZKx2) {eval(\"/*@cc_on var cheburgenRFg4 = new Date() @*/\");cheburgenRFg4[\"setUTC\"+\"Seconds" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"/``*``@`` ``}``;``)``4``v``P``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"/``*``@`` ``}``;``)``4``v``P``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXFq1(\"\")), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}