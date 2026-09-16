rule sig_20161216_61edb999057d9d6962a84499f7d590a9 {
  meta:
    description = "datamaliciousorder - file 20161216_61edb999057d9d6962a84499f7d590a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b4b8f52ef6a80730245e596b61cd11359a5d42206c9aa22213644ed08b38915"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFa7 = methCNo2[\"sp\"+\"lit\"](\"``\"); return methFa7[\"reverse" ascii
    $s2  = "function methEv1(methCNo2) {eval(\"/*@cc_on var methADt4 = new Date() @*/\");methADt4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``7``a``F``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``2``o``N``C``h``t``e``m`` ``n``r``u``t``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``1``+``1``=``7``z``H``H``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``)``2``z``B``h``t``e``m``(``1``k``N``N``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``d``S``X``h``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``)``\\x22``d``i``e``z``d``f``l``z``/``z``c``.``r``a``z`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``0`` ``=`` ``0``h``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``1``+``1``=``7``z``H``H``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``0`` ``=`` ``0``h``U``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``.`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\";``1``f``C``A``h``t``e``m`` ``+`` ``3``m``E``N``h``t``e``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEv1(\"/``*``@`` ``}``;``7``o``A``C``h``t``e``m`` ``n``r``u``t``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}