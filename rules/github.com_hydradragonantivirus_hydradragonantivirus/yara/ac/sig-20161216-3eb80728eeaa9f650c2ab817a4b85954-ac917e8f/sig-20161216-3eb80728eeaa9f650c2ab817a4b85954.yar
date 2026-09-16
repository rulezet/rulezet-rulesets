rule sig_20161216_3eb80728eeaa9f650c2ab817a4b85954 {
  meta:
    description = "datamaliciousorder - file 20161216_3eb80728eeaa9f650c2ab817a4b85954.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6a0b6cd4cd445496bed134e62344bec55bdf19f6be0b51ccbb7a768a4a986be"

  strings:
    $s1  = "function methTYd2(methMy4) {eval(\"/*@cc_on var methVm2 = new Date() @*/\");methVm2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``7``x``D``h``t``e``m`` ``+`` ``6``l``S``D``h``t``e``m`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``0`` ``=`` ``7``t``T``W``h``t``e``m`` ``r``a``v\"))), " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\"/``*``@`` ``}``;``8``u``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``1``+``1``=``2``d``C``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\"/``*``@`` ``}``;``)``0``t``Y``R``h``t``e``m``(``2``h``O`" ascii
    $s13 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCEp1 = methMy4[\"sp\"+\"lit\"](\"``\"); return methCEp1[\"reverse\"]" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\"}``;``h``t``a``P``t``r``o``h``S``.``3``w``L``S``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTYd2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``b``M``R``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}