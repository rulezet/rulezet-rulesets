rule sig_20161216_d16bbdfd1e9c0da460fa3df8c8749c2f {
  meta:
    description = "datamaliciousorder - file 20161216_d16bbdfd1e9c0da460fa3df8c8749c2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7630c18c1a6a6b081f1ece0bc327f0613ba54f84fe3f5a2b241a84ae43384e02"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOo6 = methZYz0[\"sp\"+\"lit\"](\"``\"); return methOo6[\"revers" ascii
    $s2  = "function methBQa5(methZYz0) {eval(\"/*@cc_on var methNWm7 = new Date() @*/\");methNWm7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``f``N``h``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``1``+``1``=``1``u``D``U``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``1``+``1``=``1``u``D``U``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``0`` ``=`` ``4``g``K``J``h``t``e``m`` ``r``a``v\"))), " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``w``E``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"/``*``@`` ``}``;``)``7``i``G``H``h``t``e``m``(``4``t``U`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"/``*``@`` ``}``;``)``7``i``G``H``h``t``e``m``(``4``t``U`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\"/``*``@`` ``}``;``9``l``Q``R``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBQa5(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}