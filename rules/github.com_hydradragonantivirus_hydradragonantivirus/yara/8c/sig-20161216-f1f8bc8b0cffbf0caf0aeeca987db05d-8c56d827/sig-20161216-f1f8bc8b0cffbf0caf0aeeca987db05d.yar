rule sig_20161216_f1f8bc8b0cffbf0caf0aeeca987db05d {
  meta:
    description = "datamaliciousorder - file 20161216_f1f8bc8b0cffbf0caf0aeeca987db05d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb91d2a917b1a82ccb6d4b1771037770e9878dcc86dd3c62869054019d706eb3"

  strings:
    $s1  = "function methZWn7(methNk9) {eval(\"/*@cc_on var methPe9 = new Date() @*/\");methPe9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``)``6``l``V``L``h``t``e``m``(``9``i``S`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "function methZWn7(methNk9) {eval(\"/*@cc_on var methPe9 = new Date() @*/\");methPe9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``6``z``U``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``6``z``U``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``0`` ``=`` ``7``s``Z``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``n``T``B``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZh5 = methNk9[\"sp\"+\"lit\"](\"``\"); return methZh5[\"reverse\"]()" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``p``K``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZWn7(\"/``*``@`` ``}``;``9``k``N``h``t``e``m`` ``n``r``u``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}