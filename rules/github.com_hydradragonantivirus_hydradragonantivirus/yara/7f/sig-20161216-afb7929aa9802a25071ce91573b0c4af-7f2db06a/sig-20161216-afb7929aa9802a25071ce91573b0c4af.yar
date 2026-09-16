rule sig_20161216_afb7929aa9802a25071ce91573b0c4af {
  meta:
    description = "datamaliciousorder - file 20161216_afb7929aa9802a25071ce91573b0c4af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9db9ccc4dddeea2f433c283bef77f9dcaaeb6f192f25e18df2bb383922e5a9"

  strings:
    $s1  = "function methNGf3(methEYl2) {eval(\"/*@cc_on var methSy1 = new Date() @*/\");methSy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``z``E``V``h`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``7``x``A``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methAx7 = methEYl2[\"sp\"+\"lit\"](\"``\"); return methAx7[\"reverse\"]" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``0`` ``=`` ``0``x``O``N``h``t``e``m`` ``r``a``v\"))), " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``p``K``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``7``e``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``7``x``A``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``z``E``V``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"/``*``@`` ``}``;``)``5``l``C``h``t``e``m``(``3``l``Z``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\";``1``+``1``=``7``i``F``D``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNGf3(\"\"))), 1);//////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}