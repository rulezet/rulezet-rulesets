rule sig_20161216_b133e8d303eb069c3b83bdeb54f654e9 {
  meta:
    description = "datamaliciousorder - file 20161216_b133e8d303eb069c3b83bdeb54f654e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee22bd594a63a28399b060775f68b255fd08da1fdd6590d5d56288737cdda42b"

  strings:
    $s1  = "function cheburgenBr6(cheburgenWFs6) {eval(\"/*@cc_on var cheburgenCq6 = new Date() @*/\");cheburgenCq6[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenCq6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenDi0 = cheburgenWFs6[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``\\x22``d``l``d``s``v``9``/``m``o``c``.``g``n``u``o" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``3``w``V``H``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``\\x22``\\x22`` ``+`` ``6``p``G``H``n``e``g``r``u``" ascii
    $s6  = "cheburgenDi0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``j``K``G`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``\\x22``i``e``x``w``w``r``m``a``/``m``o``c``.``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``6``s``F``W``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``\\x22``d``o``9``u``h``q``s``f``3``a``/``w``z``.``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``0``i``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``)``0``p``G``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``6``s``F``W``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\";``1``+``1``=``4``w``I``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBr6(\"/``*``@`` ``}``;``)``0``p``G``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}