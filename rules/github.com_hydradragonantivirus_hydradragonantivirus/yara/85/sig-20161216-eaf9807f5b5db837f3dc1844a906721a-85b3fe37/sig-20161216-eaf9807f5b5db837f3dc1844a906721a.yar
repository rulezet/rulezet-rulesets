rule sig_20161216_eaf9807f5b5db837f3dc1844a906721a {
  meta:
    description = "datamaliciousorder - file 20161216_eaf9807f5b5db837f3dc1844a906721a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a4a21ec6883b1102bee077a94131305c30cd60f9b9a022b875b04aa3b65e083"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methRw5 = methVPq4[\"sp\"+\"lit\"](\"``\"); return methRw5[\"revers" ascii
    $s2  = "function methOTv5(methVPq4) {eval(\"/*@cc_on var methYTn1 = new Date() @*/\");methYTn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "function methOTv5(methVPq4) {eval(\"/*@cc_on var methYTn1 = new Date() @*/\");methYTn1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``5``w``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``6``t``X``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``d``J``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``l``A``I``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``9``c``T``h``t``e``m`` ``+`` ``0``y``T``F``h``t``e``m`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``4``q``P``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``d``J``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``4``q``P``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\"/``*``@`` ``}``;``5``w``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOTv5(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}