rule sig_20161216_1386537cc344b8664b49867c53c4bf4b {
  meta:
    description = "datamaliciousorder - file 20161216_1386537cc344b8664b49867c53c4bf4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c94392103aa1227bbaad6499d89ecf9dd76e1718b62f6df27c23b4f4f204c59e"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methGx0 = methDn2[\"sp\"+\"lit\"](\"``\"); return methGx0[\"reverse\"]" ascii
    $s2  = "function methTo5(methDn2) {eval(\"/*@cc_on var methPCt7 = new Date() @*/\");methPCt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``4``m``L``h``t``e``m`` ``+`` ``5``f``W``h``t``e``m``=``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"/``*``@`` ``}``;``2``n``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``y``T``B``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``1``+``1``=``8``i``E``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``r``C``B``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``)``\\x22``e``9``5``i``d``n``u``/``m``o``c``.``n``i``j`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"/``*``@`` ``}``;``0``x``G``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "function methTo5(methDn2) {eval(\"/*@cc_on var methPCt7 = new Date() @*/\");methPCt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"/``*``@`` ``}``;``0``x``G``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``r``C``B``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``0`` ``=`` ``5``n``Q``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"/``*``@`` ``}``;``)``7``e``Y``G``h``t``e``m``(``3``t``N``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTo5(\"}``;``h``t``a``P``t``r``o``h``S``.``6``c``F``Q``h``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}