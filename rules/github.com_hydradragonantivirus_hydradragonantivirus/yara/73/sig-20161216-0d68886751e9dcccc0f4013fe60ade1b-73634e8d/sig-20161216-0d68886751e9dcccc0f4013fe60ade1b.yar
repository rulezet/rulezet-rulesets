rule sig_20161216_0d68886751e9dcccc0f4013fe60ade1b {
  meta:
    description = "datamaliciousorder - file 20161216_0d68886751e9dcccc0f4013fe60ade1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaaca18b2ce51db2a606d7af20d68b855a993195a8999fbcbb1ef1fc92981ccd"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methJm4 = methRp9[\"sp\"+\"lit\"](\"``\"); return methJm4[\"reverse\"]" ascii
    $s2  = "function methBm2(methRp9) {eval(\"/*@cc_on var methSDx9 = new Date() @*/\");methSDx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"/``*``@`` ``}``;``8``w``P``C``h``t``e``m`` ``n``r``u``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"/``*``@`` ``}``;``9``p``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"/``*``@`` ``}``;``4``m``J``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"}``;``h``t``a``P``t``r``o``h``S``.``8``w``O``U``h``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s10 = "function methBm2(methRp9) {eval(\"/*@cc_on var methSDx9 = new Date() @*/\");methSDx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``g``M``h``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"}``;``h``t``a``P``t``r``o``h``S``.``8``w``O``U``h``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\"/``*``@`` ``}``;``)``3``y``S``U``h``t``e``m``(``9``k``D``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBm2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}