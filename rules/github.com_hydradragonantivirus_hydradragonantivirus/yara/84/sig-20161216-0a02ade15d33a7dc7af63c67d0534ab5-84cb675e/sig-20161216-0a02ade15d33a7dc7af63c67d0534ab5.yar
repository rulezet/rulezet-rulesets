rule sig_20161216_0a02ade15d33a7dc7af63c67d0534ab5 {
  meta:
    description = "datamaliciousorder - file 20161216_0a02ade15d33a7dc7af63c67d0534ab5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf0bdf819d4570d2aa4d460ff4a8ece87e69cb17f0991f466f9d55b8e438d3b0"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methKg8 = methLWf8[\"sp\"+\"lit\"](\"``\"); return methKg8[\"revers" ascii
    $s2  = "function methNMv9(methLWf8) {eval(\"/*@cc_on var methOOu6 = new Date() @*/\");methOOu6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"/``*``@`` ``}``;``8``g``K``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``g``W``N``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"}``;``h``t``a``P``t``r``o``h``S``.``3``b``S``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``)``\\x22``q``x``n``n``3``g``6``a``b``r``/``t``e``n``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"/``*``@`` ``}``;``)``0``b``Y``Y``h``t``e``m``(``5``u``J`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``f``H``H`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``1``+``1``=``7``f``X``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``0`` ``=`` ``7``c``X``E``h``t``e``m`` ``r``a``v\"))), " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\"/``*``@`` ``}``;``1``z``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``f``H``H`" ascii
    $s19 = "function methNMv9(methLWf8) {eval(\"/*@cc_on var methOOu6 = new Date() @*/\");methOOu6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNMv9(\";``2``u``U``I``h``t``e``m`` ``+`` ``6``c``Y``K``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}