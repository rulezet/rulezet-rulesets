rule sig_20161216_09c1f2e663b865fa8fd8ee71a04e6914 {
  meta:
    description = "datamaliciousorder - file 20161216_09c1f2e663b865fa8fd8ee71a04e6914.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d743250736e3c3bddd0b16495429aa6bdece4721f716487715ed20f9f99f9825"

  strings:
    $s1  = "function methNFk8(methKXc6) {eval(\"/*@cc_on var methBb8 = new Date() @*/\");methBb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``0`` ``=`` ``8``v``P``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``6``c``X``K``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``0`` ``=`` ``8``v``P``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``7``v``J``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``7``v``J``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCJv7 = methKXc6[\"sp\"+\"lit\"](\"``\"); return methCJv7[\"reverse" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``)``9``e``B``R``h``t``e``m``(``2``d``C`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``7``w``I``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``1``+``1``=``1``n``C``H``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``p``T``h``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``9``g``D``I``h``t``e``m`` ``+`` ``3``p``I``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``u``S``h`" ascii
    $s19 = "function methNFk8(methKXc6) {eval(\"/*@cc_on var methBb8 = new Date() @*/\");methBb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNFk8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}