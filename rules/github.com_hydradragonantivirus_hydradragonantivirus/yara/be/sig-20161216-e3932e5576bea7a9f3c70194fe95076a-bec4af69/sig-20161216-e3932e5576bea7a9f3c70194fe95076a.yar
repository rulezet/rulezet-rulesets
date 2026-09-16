rule sig_20161216_e3932e5576bea7a9f3c70194fe95076a {
  meta:
    description = "datamaliciousorder - file 20161216_e3932e5576bea7a9f3c70194fe95076a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcdfa4503d81b2043de2be6654863f5686d04793e1781b0e55087c3f2746f35c"

  strings:
    $s1  = "function methBa3(methGd9) {eval(\"/*@cc_on var methKz4 = new Date() @*/\");methKz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methBa3(methGd9) {eval(\"/*@cc_on var methKz4 = new Date() @*/\");methKz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``0`` ``=`` ``6``b``I``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``s``K``U``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``1``+``1``=``6``i``Q``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``l``Z``h``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"}``;``h``t``a``P``t``r``o``h``S``.``5``u``O``B``h``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"/``*``@`` ``}``;``7``q``O``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"/``*``@`` ``}``;``)``9``h``P``h``t``e``m``(``7``q``U``h``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "UTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOq7 = methGd9[\"sp\"+\"lit\"](\"``\"); return methOq7[\"reverse\"]()[" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBa3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``l``Z``h``t``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}