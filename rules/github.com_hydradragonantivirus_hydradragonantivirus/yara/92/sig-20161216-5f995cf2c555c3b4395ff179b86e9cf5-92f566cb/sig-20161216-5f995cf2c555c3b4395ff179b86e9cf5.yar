rule sig_20161216_5f995cf2c555c3b4395ff179b86e9cf5 {
  meta:
    description = "datamaliciousorder - file 20161216_5f995cf2c555c3b4395ff179b86e9cf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2d005ae01e890fbf5dcb1a4314ce5a6bc1da7c301911a551e6fefce6d73202b"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZFv6 = methTHb2[\"sp\"+\"lit\"](\"``\"); return methZFv6[\"reve" ascii
    $s2  = "function methKBo8(methTHb2) {eval(\"/*@cc_on var methSBi2 = new Date() @*/\");methSBi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"/``*``@`` ``}``;``6``j``K``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"/``*``@`` ``}``;``)``9``i``I``h``t``e``m``(``7``r``A``S`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``1``+``1``=``0``d``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"/``*``@`` ``}``;``)``9``i``I``h``t``e``m``(``7``r``A``S`" ascii
    $s10 = "function methKBo8(methTHb2) {eval(\"/*@cc_on var methSBi2 = new Date() @*/\");methSBi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``f``G``S``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``q``P``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"}``;``h``t``a``P``t``r``o``h``S``.``4``k``I``L``h``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKBo8(\"}``;``h``t``a``P``t``r``o``h``S``.``4``k``I``L``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}