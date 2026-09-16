rule sig_20161216_9954abbf1c7ddd95fd99ac31dfd7ec3f {
  meta:
    description = "datamaliciousorder - file 20161216_9954abbf1c7ddd95fd99ac31dfd7ec3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a77209dfd68c3103efb68bc568f0eb75758463a8eadb2f93163042bb854875c5"

  strings:
    $s1  = "function methUj1(methRl2) {eval(\"/*@cc_on var methRe1 = new Date() @*/\");methRe1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methUj1(methRl2) {eval(\"/*@cc_on var methRe1 = new Date() @*/\");methRe1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``r``E``K``h``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\"/``*``@`` ``}``;``0``u``N``D``h``t``e``m`` ``n``r``u``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\"/``*``@`` ``}``;``)``2``m``L``M``h``t``e``m``(``7``o``S``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``i``A``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``i``A``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUj1(\"/``*``@`` ``}``;``2``l``R``h``t``e``m`` ``n``r``u``t``e``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}