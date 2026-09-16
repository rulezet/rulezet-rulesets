rule sig_20161216_63ed26033417120877d5be263d2e8b17 {
  meta:
    description = "datamaliciousorder - file 20161216_63ed26033417120877d5be263d2e8b17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2edabe9429ed5d1cbe96e1141258ae893f8a8ec811e316766ff77244e6a1df2e"

  strings:
    $s1  = "function methRAx3(methXFy5) {eval(\"/*@cc_on var methTAp5 = new Date() @*/\");methTAp5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methIh2 = methXFy5[\"sp\"+\"lit\"](\"``\"); return methIh2[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``b``K``I`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``)``6``e``O``E``h``t``e``m``(``1``f``L`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``r``L``O``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``4``z``X``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``\\x22``l``k``w``x``q``n``p``w``q``/``x``m``.``m``o" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``4``z``X``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``2``h``I``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``5``z``I``h``t``e``m`` ``+`` ``0``k``R``h``t``e``m``=`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\"/``*``@`` ``}``;``5``y``F``X``h``t``e``m`` ``n``r``u``t`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``b``K``I`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``0`` ``=`` ``5``i``X``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRAx3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}