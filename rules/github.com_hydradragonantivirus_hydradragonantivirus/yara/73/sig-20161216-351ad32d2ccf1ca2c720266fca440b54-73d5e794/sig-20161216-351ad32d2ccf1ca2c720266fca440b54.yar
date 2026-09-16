rule sig_20161216_351ad32d2ccf1ca2c720266fca440b54 {
  meta:
    description = "datamaliciousorder - file 20161216_351ad32d2ccf1ca2c720266fca440b54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c76474ec80f3cf55c79b38952c620de0bc0838420735ac6cdcd46e2b249e338"

  strings:
    $s1  = "function methIn1(methZOc9) {eval(\"/*@cc_on var methHm1 = new Date() @*/\");methHm1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\"/``*``@`` ``}``;``3``w``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``x``Y``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\"/``*``@`` ``}``;``9``c``O``Z``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``b``M``G``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\"/``*``@`` ``}``;``)``7``x``L``h``t``e``m``(``7``m``V``P``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIn1(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}