rule sig_20161216_a44658cfb5008aa2cd61a2749979ff9e {
  meta:
    description = "datamaliciousorder - file 20161216_a44658cfb5008aa2cd61a2749979ff9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d14052f151f6b4bf9b7057316acc1835e35e1d714b598be424d764553f304bd1"

  strings:
    $s1  = "function methDLm3(methEp2) {eval(\"/*@cc_on var methLb5 = new Date() @*/\");methLb5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``0`` ``=`` ``6``l``N``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``T``h`" ascii
    $s5  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMc6 = methEp2[\"sp\"+\"lit\"](\"``\"); return methMc6[\"reverse\"]()" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\"/``*``@`` ``}``;``)``5``a``R``h``t``e``m``(``6``a``A``X`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``5``k``Q``K``h``t``e``m`` ``+`` ``1``r``D``O``h``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\"}``;``h``t``a``P``t``r``o``h``S``.``2``p``V``h``t``e``m`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``1``+``1``=``6``v``G``J``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``v``T``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methDLm3(\"/``*``@`` ``}``;``)``5``a``R``h``t``e``m``(``6``a``A``X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}