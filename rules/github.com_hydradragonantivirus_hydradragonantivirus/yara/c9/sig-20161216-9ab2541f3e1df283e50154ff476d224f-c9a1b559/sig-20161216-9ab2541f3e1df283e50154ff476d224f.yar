rule sig_20161216_9ab2541f3e1df283e50154ff476d224f {
  meta:
    description = "datamaliciousorder - file 20161216_9ab2541f3e1df283e50154ff476d224f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53f909d2cef3f884e6a04297458f38089cfbe99b99504405907135112a0964b5"

  strings:
    $s1  = "function methIp7(methMZw5) {eval(\"/*@cc_on var methOr3 = new Date() @*/\");methOr3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``e``X``V``h``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``1``+``1``=``0``i``Q``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"/``*``@`` ``}``;``)``0``m``B``h``t``e``m``(``3``q``W``V``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``b``R``L``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\";``4``w``E``K``h``t``e``m`` ``+`` ``5``v``F``h``t``e``m``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``p``B``h``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"/``*``@`` ``}``;``)``0``m``B``h``t``e``m``(``3``q``W``V``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIp7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``e``X``V``h``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}