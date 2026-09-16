rule sig_20161215_abf5874668bb70cf65bbd78ce1e3abf8 {
  meta:
    description = "datamaliciousorder - file 20161215_abf5874668bb70cf65bbd78ce1e3abf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c598b32a85bc8a900e013e5f9780e7821d1773111ca48f9b216a7e2f5cb8393a"

  strings:
    $s1  = "function cheburgenHe3(cheburgenHc0) {eval(\"/*@cc_on var cheburgenIDc1 = new Date() @*/\");cheburgenIDc1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``m``C``R``n`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``8``d``S``H``n``e``g``r``u``b``e``h``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``\\x22``\\x22`` ``+`` ``7``s``I``M``n``e``g``r``u``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``s" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``\\x22``\\x22`` ``+`` ``7``s``I``M``n``e``g``r``u``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"}``;``h``t``a``P``t``r``o``h``S``.``9``m``S``n``e``g``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "function cheburgenHe3(cheburgenHc0) {eval(\"/*@cc_on var cheburgenIDc1 = new Date() @*/\");cheburgenIDc1[\"setUTC\"+\"Seconds\"]" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``8``d``S``H``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``0``c``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``m``C``R``n`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHe3(\"/``*``@`` ``}``;``)``9``v``J``Y``n``e``g``r``u``b``e``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}