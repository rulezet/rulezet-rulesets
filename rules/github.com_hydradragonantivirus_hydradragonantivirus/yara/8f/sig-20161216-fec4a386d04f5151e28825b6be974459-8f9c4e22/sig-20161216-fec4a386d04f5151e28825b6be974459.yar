rule sig_20161216_fec4a386d04f5151e28825b6be974459 {
  meta:
    description = "datamaliciousorder - file 20161216_fec4a386d04f5151e28825b6be974459.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "109a28281ba68ba97db031dcb751c26d5284c2499176e918bd77f9bda0c8f47a"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBz4 = methMc7[\"sp\"+\"lit\"](\"``\"); return methBz4[\"reverse\"]" ascii
    $s2  = "function methAk3(methMc7) {eval(\"/*@cc_on var methAZy1 = new Date() @*/\");methAZy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``1``+``1``=``8``w``C``S``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"/``*``@`` ``}``;``)``3``e``U``H``h``t``e``m``(``6``e``B``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``1``+``1``=``8``w``C``S``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``0`` ``=`` ``5``s``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"}``;``h``t``a``P``t``r``o``h``S``.``2``t``Q``h``t``e``m``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``p``I``h``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``0`` ``=`` ``5``s``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"/``*``@`` ``}``;``)``3``e``U``H``h``t``e``m``(``6``e``B``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``6``a``L``h``t``e``m`` ``+`` ``9``i``P``Y``h``t``e``m``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\"/``*``@`` ``}``;``4``z``B``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAk3(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}