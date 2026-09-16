rule sig_20161216_5d3f766627de8c5c38f03bc947866cf9 {
  meta:
    description = "datamaliciousorder - file 20161216_5d3f766627de8c5c38f03bc947866cf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d92f421716a6cfe7e19e204d34666b88eb1d1b831c50bea5c944eb7de4efcef1"

  strings:
    $s1  = "function methOs2(methEu3) {eval(\"/*@cc_on var methEq5 = new Date() @*/\");methEq5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methOs2(methEu3) {eval(\"/*@cc_on var methEq5 = new Date() @*/\");methEq5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d`" ascii
    $s6  = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBYm4 = methEu3[\"sp\"+\"lit\"](\"``\"); return methBYm4[\"reverse\"](" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\"/``*``@`` ``}``;``3``u``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``7``l``D``h``t``e``m`` ``+`` ``5``i``B``h``t``e``m``=``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``a``B``N``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``1``+``1``=``3``k``F``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOs2(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}