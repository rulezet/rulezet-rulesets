rule sig_20161216_346c90ff7c73a5c4b2fea7c04f655b71 {
  meta:
    description = "datamaliciousorder - file 20161216_346c90ff7c73a5c4b2fea7c04f655b71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eb062e62f6bbd4f437279f35cb42930fd37ce83189885fcce8ad52a137bf150"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFLf0 = methYj5[\"sp\"+\"lit\"](\"``\"); return methFLf0[\"reverse" ascii
    $s2  = "function methHc5(methYj5) {eval(\"/*@cc_on var methPVf4 = new Date() @*/\");methPVf4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``5``v``B``G``h``t``e``m`` ``+`` ``4``t``Z``h``t``e``m``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``.`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\"/``*``@`` ``}``;``0``f``L``F``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\"/``*``@`` ``}``;``5``j``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\"/``*``@`` ``}``;``)``8``k``J``H``h``t``e``m``(``0``c``P``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``1``+``1``=``2``w``H``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``0`` ``=`` ``9``g``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``1``+``1``=``2``w``H``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``e``Z``h``" ascii
    $s17 = "function methHc5(methYj5) {eval(\"/*@cc_on var methPVf4 = new Date() @*/\");methPVf4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``i``W``T``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\"/``*``@`` ``}``;``8``a``A``N``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methHc5(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}