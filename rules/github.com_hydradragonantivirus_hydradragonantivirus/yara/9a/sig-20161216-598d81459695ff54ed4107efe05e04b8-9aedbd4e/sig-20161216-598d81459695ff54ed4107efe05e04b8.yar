rule sig_20161216_598d81459695ff54ed4107efe05e04b8 {
  meta:
    description = "datamaliciousorder - file 20161216_598d81459695ff54ed4107efe05e04b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "968e90e74d3fcb47ffb4e9e104393f14f726ce5d9bdb25be36547b390ee1e30e"

  strings:
    $s1  = "function methJq4(methYLj5) {eval(\"/*@cc_on var methNa4 = new Date() @*/\");methNa4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\"/``*``@`` ``}``;``8``p``G``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\"/``*``@`` ``}``;``)``7``v``E``D``h``t``e``m``(``6``y``B``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\"/``*``@`` ``}``;``0``h``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``1``+``1``=``8``y``S``Z``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\"/``*``@`` ``}``;``0``h``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``m``X``h``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``1``e``D``h``t``e``m`` ``+`` ``0``k``S``h``t``e``m``=``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJq4(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r`" ascii
    $s20 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methGp8 = methYLj5[\"sp\"+\"lit\"](\"``\"); return methGp8[\"reverse\"](" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}