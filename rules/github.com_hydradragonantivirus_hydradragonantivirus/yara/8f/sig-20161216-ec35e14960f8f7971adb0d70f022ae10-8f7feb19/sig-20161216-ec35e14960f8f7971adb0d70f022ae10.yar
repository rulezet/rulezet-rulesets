rule sig_20161216_ec35e14960f8f7971adb0d70f022ae10 {
  meta:
    description = "datamaliciousorder - file 20161216_ec35e14960f8f7971adb0d70f022ae10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36cce1c471222f7a9469ae62cd7184cc5d6e43d7af0e465864d7dc49d28553d9"

  strings:
    $s1  = "function cheburgenHWi3(cheburgenKPr3) {eval(\"/*@cc_on var cheburgenYo3 = new Date() @*/\");cheburgenYo3[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenYo3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAv8 = cheburgenKPr3[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``b``A``R``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"}``;``h``t``a``P``t``r``o``h``S``.``3``l``V``E``n``e``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"}``;``h``t``a``P``t``r``o``h``S``.``3``l``V``E``n``e``g" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``0`` ``=`` ``4``u``N``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"/``*``@`` ``}``;``)``6``m``D``M``n``e``g``r``u``b``e``h" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``\\x22``\\x22`` ``+`` ``8``u``D``U``n``e``g``r``u`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``\\x22``h``h``3``m``u``5``e``z``t``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"/``*``@`` ``}``;``8``v``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"/``*``@`` ``}``;``3``r``P``K``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``6``l``K``n``e``g``r``u``b``e``h``c`` ``+`` ``4``d``J" ascii
    $s19 = "function cheburgenHWi3(cheburgenKPr3) {eval(\"/*@cc_on var cheburgenYo3 = new Date() @*/\");cheburgenYo3[\"setUTC\"+\"Seconds\"]" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHWi3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}