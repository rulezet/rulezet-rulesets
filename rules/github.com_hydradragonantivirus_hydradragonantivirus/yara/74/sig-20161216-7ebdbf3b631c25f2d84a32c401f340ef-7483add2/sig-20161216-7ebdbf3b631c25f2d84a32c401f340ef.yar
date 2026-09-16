rule sig_20161216_7ebdbf3b631c25f2d84a32c401f340ef {
  meta:
    description = "datamaliciousorder - file 20161216_7ebdbf3b631c25f2d84a32c401f340ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6eb1f5d9720f85fc237ae9d1793448a7b0d4c3b03132f99e0c49e1717875d72"

  strings:
    $s1  = "function methOUw5(methBOo1) {eval(\"/*@cc_on var methYz7 = new Date() @*/\");methYz7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\"/``*``@`` ``}``;``1``o``O``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``f``R``h`" ascii
    $s5  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCKg3 = methBOo1[\"sp\"+\"lit\"](\"``\"); return methCKg3[\"reverse" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``g``P``D``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\"/``*``@`` ``}``;``3``g``K``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``0`` ``=`` ``6``t``H``A``h``t``e``m`` ``r``a``v\"))), " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``f``R``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``1``+``1``=``2``j``N``C``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\"}``;``h``t``a``P``t``r``o``h``S``.``9``p``G``L``h``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``8``l``F``Q``h``t``e``m`` ``+`` ``4``g``C``Q``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUw5(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}