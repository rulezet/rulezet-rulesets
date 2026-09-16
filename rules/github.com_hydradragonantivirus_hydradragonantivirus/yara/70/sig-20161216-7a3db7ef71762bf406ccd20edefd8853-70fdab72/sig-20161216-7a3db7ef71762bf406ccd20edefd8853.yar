rule sig_20161216_7a3db7ef71762bf406ccd20edefd8853 {
  meta:
    description = "datamaliciousorder - file 20161216_7a3db7ef71762bf406ccd20edefd8853.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388c5a95c5ba93a21cd01356010d1f3c40e10108c00d9990bf61c5c0e73085f3"

  strings:
    $s1  = "function cheburgenVk6(cheburgenYo7) {eval(\"/*@cc_on var cheburgenQUu9 = new Date() @*/\");cheburgenQUu9[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``g``A``n``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"/``*``@`` ``}``;``8``g``B``E``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``\\x22``\\x22`` ``+`` ``0``z``C``T``n``e``g``r``u``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"/``*``@`` ``}``;``)``7``i``Y``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"/``*``@`` ``}``;``7``o``Y``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``1``+``1``=``8``g``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``\\x22``\\x22`` ``+`` ``0``z``C``T``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\"}``;``h``t``a``P``t``r``o``h``S``.``9``n``E``n``e``g``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "function cheburgenVk6(cheburgenYo7) {eval(\"/*@cc_on var cheburgenQUu9 = new Date() @*/\");cheburgenQUu9[\"setUTC\"+\"Seconds\"]" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVk6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}