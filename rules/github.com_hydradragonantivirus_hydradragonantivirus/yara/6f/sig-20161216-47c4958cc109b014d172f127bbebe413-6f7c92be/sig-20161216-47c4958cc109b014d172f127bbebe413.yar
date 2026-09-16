rule sig_20161216_47c4958cc109b014d172f127bbebe413 {
  meta:
    description = "datamaliciousorder - file 20161216_47c4958cc109b014d172f127bbebe413.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2fb41517bdc7c403e218684d5d4427e08620cdac4f5499ee61e2fb5e04efa8"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPVb4 = methPn6[\"sp\"+\"lit\"](\"``\"); return methPVb4[\"reverse" ascii
    $s2  = "function methRs6(methPn6) {eval(\"/*@cc_on var methVYo6 = new Date() @*/\");methVYo6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"/``*``@`` ``}``;``4``b``V``P``h``t``e``m`` ``n``r``u``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``w``P``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``1``+``1``=``7``k``W``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``g``O``E``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"}``;``h``t``a``P``t``r``o``h``S``.``6``e``M``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"/``*``@`` ``}``;``6``n``P``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"/``*``@`` ``}``;``5``s``W``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\"/``*``@`` ``}``;``)``9``h``W``B``h``t``e``m``(``9``o``V``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``w``P``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRs6(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}