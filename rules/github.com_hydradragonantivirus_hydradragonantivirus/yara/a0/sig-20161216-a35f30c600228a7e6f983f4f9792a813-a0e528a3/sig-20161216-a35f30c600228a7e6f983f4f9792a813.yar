rule sig_20161216_a35f30c600228a7e6f983f4f9792a813 {
  meta:
    description = "datamaliciousorder - file 20161216_a35f30c600228a7e6f983f4f9792a813.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7672b476f58fd0690cceed84d198e81aa9d8fcbc2d1b12aeb6af87eef3e37da"

  strings:
    $s1  = "function methHYf5(methWo4) {eval(\"/*@cc_on var methXf1 = new Date() @*/\");methXf1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``1``+``1``=``4``y``I``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSWb8 = methWo4[\"sp\"+\"lit\"](\"``\"); return methSWb8[\"reverse\"]" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``1``+``1``=``4``y``I``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\"/``*``@`` ``}``;``3``h``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``0`` ``=`` ``0``j``C``Q``h``t``e``m`` ``r``a``v\"))), " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``w``K``T`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``i``R``A``h``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHYf5(\"/``*``@`` ``}``;``4``o``W``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}