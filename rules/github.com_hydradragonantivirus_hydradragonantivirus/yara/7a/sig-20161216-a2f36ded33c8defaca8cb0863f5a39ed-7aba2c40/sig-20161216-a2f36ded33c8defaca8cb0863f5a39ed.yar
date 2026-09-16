rule sig_20161216_a2f36ded33c8defaca8cb0863f5a39ed {
  meta:
    description = "datamaliciousorder - file 20161216_a2f36ded33c8defaca8cb0863f5a39ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a085c89057a8c5ccb66032d4c19e34a852640b7a869292874c7e714a741cda06"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methMQp7 = methAb9[\"sp\"+\"lit\"](\"``\"); return methMQp7[\"reverse" ascii
    $s2  = "function methKl8(methAb9) {eval(\"/*@cc_on var methJKj0 = new Date() @*/\");methJKj0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``f``P``W``h``t``e``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``n``U``h``t``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"/``*``@`` ``}``;``)``2``p``Q``h``t``e``m``(``3``h``K``Q``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"}``;``h``t``a``P``t``r``o``h``S``.``0``f``P``W``h``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``1``l``O``L``h``t``e``m`` ``+`` ``9``p``W``A``h``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``0`` ``=`` ``9``f``E``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``.`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"/``*``@`` ``}``;``7``p``Q``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``0`` ``=`` ``9``f``E``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``g``D``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKl8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}