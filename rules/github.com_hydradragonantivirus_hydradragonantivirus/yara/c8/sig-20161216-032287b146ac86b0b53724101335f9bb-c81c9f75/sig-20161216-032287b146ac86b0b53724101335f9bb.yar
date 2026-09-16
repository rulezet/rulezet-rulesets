rule sig_20161216_032287b146ac86b0b53724101335f9bb {
  meta:
    description = "datamaliciousorder - file 20161216_032287b146ac86b0b53724101335f9bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab8135c4eb40bdd00d3ce5cc1c6d3bb22269ea82c2622923a2c5af77da5cd09"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZZr9 = methGLr1[\"sp\"+\"lit\"](\"``\"); return methZZr9[\"reve" ascii
    $s2  = "function methABx3(methGLr1) {eval(\"/*@cc_on var methGUw9 = new Date() @*/\");methGUw9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``i``C``h``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``2``h``I``A``h``t``e``m`` ``+`` ``3``k``I``J``h``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\"/``*``@`` ``}``;``9``r``Z``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\"/``*``@`` ``}``;``0``n``A``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s14 = "function methABx3(methGLr1) {eval(\"/*@cc_on var methGUw9 = new Date() @*/\");methGUw9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``2``h``I``A``h``t``e``m`` ``+`` ``3``k``I``J``h``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\"}``;``h``t``a``P``t``r``o``h``S``.``7``t``W``Y``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methABx3(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}