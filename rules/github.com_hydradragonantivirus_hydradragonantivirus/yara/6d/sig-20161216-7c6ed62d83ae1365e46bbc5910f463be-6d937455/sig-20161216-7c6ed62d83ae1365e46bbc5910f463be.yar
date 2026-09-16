rule sig_20161216_7c6ed62d83ae1365e46bbc5910f463be {
  meta:
    description = "datamaliciousorder - file 20161216_7c6ed62d83ae1365e46bbc5910f463be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f7e2fea442df5731c88fb80b89e113a3e17dd6f7839e9a07be689fb7a8a455c"

  strings:
    $s1  = "function methUm4(methWm0) {eval(\"/*@cc_on var methLo3 = new Date() @*/\");methLo3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methUm4(methWm0) {eval(\"/*@cc_on var methLo3 = new Date() @*/\");methLo3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"/``*``@`` ``}``;``7``d``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"/``*``@`` ``}``;``7``d``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"/``*``@`` ``}``;``0``e``B``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``G``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"/``*``@`` ``}``;``0``e``B``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``6``g``L``h``t``e``m`` ``+`` ``5``s``W``A``h``t``e``m``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``l``U``h``t``e``m``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methUm4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``G``h``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}