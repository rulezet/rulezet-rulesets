rule sig_20161216_d8f2e165fb6c20cba04ff1aff10ce537 {
  meta:
    description = "datamaliciousorder - file 20161216_d8f2e165fb6c20cba04ff1aff10ce537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2086255f20a7d019388b298805cbd26df33d93316b2839ddfc2a387dd02d3e54"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNd1 = methHZd7[\"sp\"+\"lit\"](\"``\"); return methNd1[\"reverse" ascii
    $s2  = "function methNp3(methHZd7) {eval(\"/*@cc_on var methTDz0 = new Date() @*/\");methTDz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii
    $s8  = "function methNp3(methHZd7) {eval(\"/*@cc_on var methTDz0 = new Date() @*/\");methTDz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"/``*``@`` ``}``;``)``4``x``O``O``h``t``e``m``(``7``q``P``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``9``k``D``K``h``t``e``m`` ``+`` ``9``s``Y``h``t``e``m``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"/``*``@`` ``}``;``4``o``N``X``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``0`` ``=`` ``9``t``I``O``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\"/``*``@`` ``}``;``7``d``Z``H``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNp3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}