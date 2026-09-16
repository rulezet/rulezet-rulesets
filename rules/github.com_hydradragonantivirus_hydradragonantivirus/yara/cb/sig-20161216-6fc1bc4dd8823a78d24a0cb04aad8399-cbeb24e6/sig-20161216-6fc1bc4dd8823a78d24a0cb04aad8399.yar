rule sig_20161216_6fc1bc4dd8823a78d24a0cb04aad8399 {
  meta:
    description = "datamaliciousorder - file 20161216_6fc1bc4dd8823a78d24a0cb04aad8399.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e40f9cb81ad77ebd1d807de7b752b3c241accd4496a2cb9fd9f98bb83311830"

  strings:
    $s1  = "function methUo3(methGZj3) {eval(\"/*@cc_on var methEc9 = new Date() @*/\");methEc9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"/``*``@`` ``}``;``0``x``B``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``3``z``N``h``t``e``m`` ``+`` ``5``j``A``h``t``e``m``=``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"/``*``@`` ``}``;``3``j``Z``G``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``1``+``1``=``1``k``Q``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"/``*``@`` ``}``;``9``p``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``x``V``I``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUo3(\"}``;``h``t``a``P``t``r``o``h``S``.``7``d``H``h``t``e``m``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}