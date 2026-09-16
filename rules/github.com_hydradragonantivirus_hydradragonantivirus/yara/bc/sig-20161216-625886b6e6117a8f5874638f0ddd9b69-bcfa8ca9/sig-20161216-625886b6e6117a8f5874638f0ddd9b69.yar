rule sig_20161216_625886b6e6117a8f5874638f0ddd9b69 {
  meta:
    description = "datamaliciousorder - file 20161216_625886b6e6117a8f5874638f0ddd9b69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1171de2c8e3be3f910110a82530782fa16cfac84c0d1158ea855a17d9da2efc0"

  strings:
    $s1  = "function methTXb3(methKa4) {eval(\"/*@cc_on var methMIy3 = new Date() @*/\");methMIy3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFWx9 = methKa4[\"sp\"+\"lit\"](\"``\"); return methFWx9[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``1``+``1``=``5``y``Y``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\"/``*``@`` ``}``;``)``9``o``U``E``h``t``e``m``(``3``w``H`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\"/``*``@`` ``}``;``9``x``W``F``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``e``F``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``8``b``P``h``t``e``m`` ``+`` ``1``k``H``P``h``t``e``m`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``8``b``P``h``t``e``m`` ``+`` ``1``k``H``P``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``e``F``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``0`` ``=`` ``1``j``J``I``h``t``e``m`` ``r``a``v\"))), " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTXb3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}