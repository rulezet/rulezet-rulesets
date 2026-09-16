rule sig_20161216_9403c6e6bf65ca0b5a7d7ef3bbdb387a {
  meta:
    description = "datamaliciousorder - file 20161216_9403c6e6bf65ca0b5a7d7ef3bbdb387a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf74008fe3233aebf7b65bef9c16403bb5e3166d28957cddb6b936cb44288e0"

  strings:
    $s1  = "function methCa0(methTKc1) {eval(\"/*@cc_on var methUv3 = new Date() @*/\");methUv3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUl9 = methTKc1[\"sp\"+\"lit\"](\"``\"); return methUl9[\"reverse\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``0`` ``=`` ``0``d``Z``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``1``g``Q``B``h``t``e``m`` ``+`` ``1``y``L``Y``h``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s10 = "function methCa0(methTKc1) {eval(\"/*@cc_on var methUv3 = new Date() @*/\");methUv3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\"/``*``@`` ``}``;``1``c``K``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\"/``*``@`` ``}``;``3``x``K``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\"/``*``@`` ``}``;``1``c``K``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``l``J``Y``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCa0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}