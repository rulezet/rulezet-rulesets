rule sig_20161216_4acbd5ee8b220cc941caccc96e35ca22 {
  meta:
    description = "datamaliciousorder - file 20161216_4acbd5ee8b220cc941caccc96e35ca22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82f2a7ec82c0fd900d43fe3e65d14ae868ae0b08ee7aa9f0d2135c1f2c0c1307"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWOq8 = methUEl0[\"sp\"+\"lit\"](\"``\"); return methWOq8[\"reve" ascii
    $s2  = "function methQOk2(methUEl0) {eval(\"/*@cc_on var methVAb7 = new Date() @*/\");methVAb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``k``W``B``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"/``*``@`` ``}``;``8``q``O``W``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``u``O``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``4``i``V``O``h``t``e``m`` ``+`` ``5``v``A``h``t``e``m`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"}``;``h``t``a``P``t``r``o``h``S``.``5``u``O``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``4``i``V``O``h``t``e``m`` ``+`` ``5``v``A``h``t``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"/``*``@`` ``}``;``)``9``i``F``h``t``e``m``(``8``p``G``O`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``0`` ``=`` ``7``a``F``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"/``*``@`` ``}``;``)``9``i``F``h``t``e``m``(``8``p``G``O`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``k``W``B``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methQOk2(\";``0`` ``=`` ``7``a``F``h``t``e``m`` ``r``a``v\"))), 1);" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}