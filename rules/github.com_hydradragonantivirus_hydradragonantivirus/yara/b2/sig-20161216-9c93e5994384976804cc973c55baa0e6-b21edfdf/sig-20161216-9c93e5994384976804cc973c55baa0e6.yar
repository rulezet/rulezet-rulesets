rule sig_20161216_9c93e5994384976804cc973c55baa0e6 {
  meta:
    description = "datamaliciousorder - file 20161216_9c93e5994384976804cc973c55baa0e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4502b79e135275d68e23645a79670b57ad6c0e734f271270e8acb1e4d7704dee"

  strings:
    $s1  = "20\");if (cheburgenXd3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMRb3 = cheburgenRAo0[\"split\"](\"``" ascii
    $s2  = "function cheburgenZm8(cheburgenRAo0) {eval(\"/*@cc_on var cheburgenXd3 = new Date() @*/\");cheburgenXd3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``." ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``\\x22``\\x22`` ``+`` ``6``r``D``n``e``g``r``u``b``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``1``+``1``=``9``u``O``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"/``*``@`` ``}``;``3``b``R``M``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"/``*``@`` ``}``;``)``2``y``W``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``1``+``1``=``9``u``O``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"/``*``@`` ``}``;``5``s``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``y" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``\\x22``\\x22`` ``+`` ``6``r``D``n``e``g``r``u``b``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``t``E``K`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"}``;``h``t``a``P``t``r``o``h``S``.``6``k``H``A``n``e``g`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"/``*``@`` ``}``;``0``o``A``R``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``0`` ``=`` ``9``d``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``h``O``V``n`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZm8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``t``E``K`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}