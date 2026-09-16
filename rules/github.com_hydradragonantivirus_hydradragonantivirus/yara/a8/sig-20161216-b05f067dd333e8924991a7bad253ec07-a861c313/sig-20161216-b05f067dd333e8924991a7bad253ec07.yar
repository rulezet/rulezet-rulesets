rule sig_20161216_b05f067dd333e8924991a7bad253ec07 {
  meta:
    description = "datamaliciousorder - file 20161216_b05f067dd333e8924991a7bad253ec07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c95a1d0af1505bbc863df53a49b03a93be17e376fdcc4552148ab50660586b2d"

  strings:
    $s1  = "function methXb5(methXo6) {eval(\"/*@cc_on var methZIa3 = new Date() @*/\");methZIa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methEJc0 = methXo6[\"sp\"+\"lit\"](\"``\"); return methEJc0[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"/``*``@`` ``}``;``2``x``A``B``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``1``+``1``=``9``o``J``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"}``;``h``t``a``P``t``r``o``h``S``.``6``l``L``Q``h``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"/``*``@`` ``}``;``6``o``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"/``*``@`` ``}``;``0``c``J``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"/``*``@`` ``}``;``2``x``A``B``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"}``;``h``t``a``P``t``r``o``h``S``.``6``l``L``Q``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"/``*``@`` ``}``;``)``4``l``W``D``h``t``e``m``(``1``w``F``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``0`` ``=`` ``5``g``K``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``0`` ``=`` ``5``g``K``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXb5(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}