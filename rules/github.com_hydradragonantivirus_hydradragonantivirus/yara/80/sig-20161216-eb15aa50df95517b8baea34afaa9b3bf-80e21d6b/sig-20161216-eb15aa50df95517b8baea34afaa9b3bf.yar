rule sig_20161216_eb15aa50df95517b8baea34afaa9b3bf {
  meta:
    description = "datamaliciousorder - file 20161216_eb15aa50df95517b8baea34afaa9b3bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f71022702d8f2a34e3f714e9cf3e674d58a7c37b14d9b176862a805a4f909e79"

  strings:
    $s1  = "function methVTs0(methCf4) {eval(\"/*@cc_on var methBQp6 = new Date() @*/\");methBQp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCQf8 = methCf4[\"sp\"+\"lit\"](\"``\"); return methCQf8[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``1``+``1``=``0``c``J``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``z``R``W``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"/``*``@`` ``}``;``8``f``Q``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``z``R``W``h`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``0`` ``=`` ``9``o``Y``F``h``t``e``m`` ``r``a``v\"))), " ascii
    $s9  = "function methVTs0(methCf4) {eval(\"/*@cc_on var methBQp6 = new Date() @*/\");methBQp6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"}``;``h``t``a``P``t``r``o``h``S``.``5``e``E``U``h``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"/``*``@`` ``}``;``8``f``Q``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\"/``*``@`` ``}``;``)``8``r``S``h``t``e``m``(``2``b``T``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVTs0(\";``)``\\x22``v``h``i``g``n``/``u``a``.``m``o``c``.``e``m" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}