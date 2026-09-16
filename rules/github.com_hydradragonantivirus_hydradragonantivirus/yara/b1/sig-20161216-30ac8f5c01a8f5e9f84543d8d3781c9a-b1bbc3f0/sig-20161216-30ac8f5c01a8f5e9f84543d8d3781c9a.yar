rule sig_20161216_30ac8f5c01a8f5e9f84543d8d3781c9a {
  meta:
    description = "datamaliciousorder - file 20161216_30ac8f5c01a8f5e9f84543d8d3781c9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da05aa145dc8b21afcbc200258ab8a6254141b84b2d844698250d5d89b81214b"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methVk1 = methHYu9[\"sp\"+\"lit\"](\"``\"); return methVk1[\"revers" ascii
    $s2  = "function methYZl9(methHYu9) {eval(\"/*@cc_on var methREt6 = new Date() @*/\");methREt6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"/``*``@`` ``}``;``9``z``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"/``*``@`` ``}``;``1``k``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"/``*``@`` ``}``;``)``3``j``Y``h``t``e``m``(``2``j``Z``O`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``1``+``1``=``0``c``T``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZl9(\";``8``a``N``J``h``t``e``m`` ``+`` ``0``v``B``h``t``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}