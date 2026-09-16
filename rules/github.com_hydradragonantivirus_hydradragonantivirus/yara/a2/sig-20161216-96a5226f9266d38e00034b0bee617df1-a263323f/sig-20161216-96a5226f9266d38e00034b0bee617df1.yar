rule sig_20161216_96a5226f9266d38e00034b0bee617df1 {
  meta:
    description = "datamaliciousorder - file 20161216_96a5226f9266d38e00034b0bee617df1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d1a2dd955a74c4b8e004898f0b2ba4294678c78f0a61640fdbf4432f68c846e"

  strings:
    $s1  = "function methVIu7(methHd6) {eval(\"/*@cc_on var methWLk1 = new Date() @*/\");methWLk1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methTHu5 = methHd6[\"sp\"+\"lit\"](\"``\"); return methTHu5[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\"/``*``@`` ``}``;``5``u``H``T``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``9``h``L``h``t``e``m`` ``+`` ``7``r``A``T``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``1``+``1``=``3``g``K``W``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``9``h``L``h``t``e``m`` ``+`` ``7``r``A``T``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "function methVIu7(methHd6) {eval(\"/*@cc_on var methWLk1 = new Date() @*/\");methWLk1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVIu7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}