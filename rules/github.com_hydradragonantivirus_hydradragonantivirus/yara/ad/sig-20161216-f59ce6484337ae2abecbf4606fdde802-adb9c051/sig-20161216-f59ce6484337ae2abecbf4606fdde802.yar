rule sig_20161216_f59ce6484337ae2abecbf4606fdde802 {
  meta:
    description = "datamaliciousorder - file 20161216_f59ce6484337ae2abecbf4606fdde802.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79723bd1d46e011eff7780df332b5f26dcae5ef701dd1f9d3df71d4bdad61d4f"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methGKk7 = methAc6[\"sp\"+\"lit\"](\"``\"); return methGKk7[\"reverse" ascii
    $s2  = "function methUe3(methAc6) {eval(\"/*@cc_on var methMFg3 = new Date() @*/\");methMFg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``0`` ``=`` ``6``d``C``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``u``N``B``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``1``+``1``=``8``l``G``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``d``v``c``t``f``/``z``c``.``y``n``i``t``e``l`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``4``g``M``h``t``e``m`` ``+`` ``4``k``Q``E``h``t``e``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"/``*``@`` ``}``;``6``c``A``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``u``N``B``h``" ascii
    $s17 = "function methUe3(methAc6) {eval(\"/*@cc_on var methMFg3 = new Date() @*/\");methMFg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"/``*``@`` ``}``;``)``3``w``R``F``h``t``e``m``(``3``n``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUe3(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}