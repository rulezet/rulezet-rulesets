rule sig_20161216_9d93b910b6093e8f41afa7ba0324a866 {
  meta:
    description = "datamaliciousorder - file 20161216_9d93b910b6093e8f41afa7ba0324a866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af8c26ab1531ae29ac0831608bc65629a6cc7860008077c8c27b12e6d615c850"

  strings:
    $s1  = "function methNg6(methTUg3) {eval(\"/*@cc_on var methXd2 = new Date() @*/\");methXd2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"/``*``@`` ``}``;``)``9``l``K``I``h``t``e``m``(``6``u``H``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``0`` ``=`` ``0``q``X``L``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"}``;``h``t``a``P``t``r``o``h``S``.``4``q``L``P``h``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"/``*``@`` ``}``;``3``g``U``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``b``Q``J``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``l``F``P``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``7``k``L``X``h``t``e``m`` ``+`` ``7``x``R``L``h``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``1``+``1``=``6``f``L``P``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNg6(\"/``*``@`` ``}``;``2``r``L``Q``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "function methNg6(methTUg3) {eval(\"/*@cc_on var methXd2 = new Date() @*/\");methXd2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}