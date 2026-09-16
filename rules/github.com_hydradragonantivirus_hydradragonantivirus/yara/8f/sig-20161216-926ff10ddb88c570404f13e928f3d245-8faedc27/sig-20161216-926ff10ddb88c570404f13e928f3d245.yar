rule sig_20161216_926ff10ddb88c570404f13e928f3d245 {
  meta:
    description = "datamaliciousorder - file 20161216_926ff10ddb88c570404f13e928f3d245.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12ef2da965c4b6b421a0f4ecf73d37e51e6a42f59d3cbcbee9a336c8fc655219"

  strings:
    $s1  = "function cheburgenXa6(cheburgenHj7) {eval(\"/*@cc_on var cheburgenVGg5 = new Date() @*/\");cheburgenVGg5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``)``0``x``P``M``n``e``g``r``u``b``e``h`" ascii
    $s3  = "n cheburgenFLh3[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"}``;``h``t``a``P``t``r``o``h``S``.``0``e``S``S``n``e``g`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``7``j``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``3``n``J``n``e``g``r``u``b``e``h``c`` ``+`` ``5``h``K`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``9``i``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``1``+``1``=``1``w``L``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``3``h``L``F``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``9``i``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``d``C``K``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``b``P``n`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenXa6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``d``C``K``n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}