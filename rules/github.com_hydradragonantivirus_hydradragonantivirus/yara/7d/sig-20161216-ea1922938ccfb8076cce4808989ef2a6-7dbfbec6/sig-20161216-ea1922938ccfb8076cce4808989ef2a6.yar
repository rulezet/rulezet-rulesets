rule sig_20161216_ea1922938ccfb8076cce4808989ef2a6 {
  meta:
    description = "datamaliciousorder - file 20161216_ea1922938ccfb8076cce4808989ef2a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "772052373a611a768e230b67cb7995844388bf9a7d40c7627260ce4634c9ecac"

  strings:
    $s1  = "function cheburgenVp7(cheburgenCm4) {eval(\"/*@cc_on var cheburgenNVz4 = new Date() @*/\");cheburgenNVz4[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenNVz4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenCa3 = cheburgenCm4[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "function cheburgenVp7(cheburgenCm4) {eval(\"/*@cc_on var cheburgenNVz4 = new Date() @*/\");cheburgenNVz4[\"setUTC\"+\"Seconds\"]" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"}``;``h``t``a``P``t``r``o``h``S``.``0``j``N``N``n``e``g`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``0``i``I``S``n``e``g``r``u``b``e``h``c`` ``+`` ``0``w`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"/``*``@`` ``}``;``3``a``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"/``*``@`` ``}``;``4``m``C``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"}``;``h``t``a``P``t``r``o``h``S``.``0``j``N``N``n``e``g`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"/``*``@`` ``}``;``7``e``J``n``e``g``r``u``b``e``h``c`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"/``*``@`` ``}``;``)``7``p``R``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVp7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}