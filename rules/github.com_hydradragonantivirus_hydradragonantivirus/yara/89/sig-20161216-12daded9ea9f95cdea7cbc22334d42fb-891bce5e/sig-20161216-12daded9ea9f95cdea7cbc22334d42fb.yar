rule sig_20161216_12daded9ea9f95cdea7cbc22334d42fb {
  meta:
    description = "datamaliciousorder - file 20161216_12daded9ea9f95cdea7cbc22334d42fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fd17f31db0c07aa041918c8d458e5f484fa0576100dc13fd8415e4e73b296bd"

  strings:
    $s1  = "function methFp0(methOw5) {eval(\"/*@cc_on var methVn7 = new Date() @*/\");methVn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methFp0(methOw5) {eval(\"/*@cc_on var methVn7 = new Date() @*/\");methVn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``1``+``1``=``4``r``B``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``1``+``1``=``4``r``B``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"/``*``@`` ``}``;``2``o``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``b``S``h``t``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"/``*``@`` ``}``;``5``w``O``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``0`` ``=`` ``2``e``K``U``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"}``;``h``t``a``P``t``r``o``h``S``.``7``s``X``h``t``e``m``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"/``*``@`` ``}``;``2``o``X``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``D``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFp0(\"/``*``@`` ``}``;``5``w``O``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}