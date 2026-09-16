rule sig_20161216_f8437f729cd7686ff580715d6f2c24de {
  meta:
    description = "datamaliciousorder - file 20161216_f8437f729cd7686ff580715d6f2c24de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c48afc84b2f0d910c3cff41309d832199f6ad28daecf30669438570511a21cbe"

  strings:
    $s1  = "function methLu8(methGVp5) {eval(\"/*@cc_on var methXJo2 = new Date() @*/\");methXJo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYLh9 = methGVp5[\"sp\"+\"lit\"](\"``\"); return methYLh9[\"rever" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"/``*``@`` ``}``;``5``p``V``G``h``t``e``m`` ``n``r``u``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``0`` ``=`` ``0``x``V``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"/``*``@`` ``}``;``9``h``L``Y``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``f``Y``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"/``*``@`` ``}``;``6``e``E``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "function methLu8(methGVp5) {eval(\"/*@cc_on var methXJo2 = new Date() @*/\");methXJo2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``f``Y``h``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``z``B``P``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\"/``*``@`` ``}``;``9``h``L``Y``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methLu8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}