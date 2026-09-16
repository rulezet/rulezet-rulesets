rule sig_20161216_da08fa1e523f8cc33a891450266648cf {
  meta:
    description = "datamaliciousorder - file 20161216_da08fa1e523f8cc33a891450266648cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d874317e4be29fef9c51d39e769c90d594b2ff58074b811181edfe6090fd016"

  strings:
    $s1  = "function methWq3(methPKg9) {eval(\"/*@cc_on var methMj3 = new Date() @*/\");methMj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``c``Q``Q``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``0`` ``=`` ``9``x``X``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"/``*``@`` ``}``;``4``f``E``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``c``Q``Q``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"/``*``@`` ``}``;``)``9``i``L``h``t``e``m``(``4``f``J``h``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"}``;``h``t``a``P``t``r``o``h``S``.``8``m``E``h``t``e``m``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\"}``;``h``t``a``P``t``r``o``h``S``.``8``m``E``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWq3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}