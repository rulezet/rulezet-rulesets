rule sig_20161216_44b6bec056ebb259776fb8bba1ecbc34 {
  meta:
    description = "datamaliciousorder - file 20161216_44b6bec056ebb259776fb8bba1ecbc34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c74b9c341ddff56eda23d4ff1357032af1abcdcee91de7bab0afeeaf175425a"

  strings:
    $s1  = "function methTt9(methIEx1) {eval(\"/*@cc_on var methOb7 = new Date() @*/\");methOb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCb7 = methIEx1[\"sp\"+\"lit\"](\"``\"); return methCb7[\"reverse\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``0`` ``=`` ``4``o``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"/``*``@`` ``}``;``1``x``E``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s8  = "function methTt9(methIEx1) {eval(\"/*@cc_on var methOb7 = new Date() @*/\");methOb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"/``*``@`` ``}``;``1``x``E``I``h``t``e``m`` ``n``r``u``t``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``s``M``h``t``e``m``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``3``y``B``A``h``t``e``m`` ``+`` ``2``s``X``W``h``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``0`` ``=`` ``4``o``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``1``+``1``=``6``i``J``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\"/``*``@`` ``}``;``)``9``w``G``C``h``t``e``m``(``1``p``J``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTt9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``c``R``R``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}