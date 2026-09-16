rule sig_20161216_d4474520115990a5542a64ec98b9798b {
  meta:
    description = "datamaliciousorder - file 20161216_d4474520115990a5542a64ec98b9798b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50c85074f24eaac9e08881d2d5a7a47cca25c4fcd2161f1e608d9e5551910aed"

  strings:
    $s1  = "function methEz8(methBk6) {eval(\"/*@cc_on var methDBn7 = new Date() @*/\");methDBn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNz4 = methBk6[\"sp\"+\"lit\"](\"``\"); return methNz4[\"reverse\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\"/``*``@`` ``}``;``4``z``N``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``a``H``h``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s12 = "function methEz8(methBk6) {eval(\"/*@cc_on var methDBn7 = new Date() @*/\");methDBn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``0`` ``=`` ``1``q``E``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\"/``*``@`` ``}``;``9``o``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``.`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\"/``*``@`` ``}``;``)``1``o``A``T``h``t``e``m``(``3``h``F``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\"/``*``@`` ``}``;``9``o``D``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEz8(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}