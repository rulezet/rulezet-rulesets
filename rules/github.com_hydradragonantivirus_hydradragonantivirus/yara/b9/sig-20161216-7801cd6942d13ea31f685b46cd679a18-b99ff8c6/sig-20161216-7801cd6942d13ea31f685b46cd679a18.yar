rule sig_20161216_7801cd6942d13ea31f685b46cd679a18 {
  meta:
    description = "datamaliciousorder - file 20161216_7801cd6942d13ea31f685b46cd679a18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9c8b7fce6ad44fdb0bcdc1001456fd827a4cb45d8936cfaffcd554ef71bfe1"

  strings:
    $s1  = "function methPs8(methQt7) {eval(\"/*@cc_on var methLJu7 = new Date() @*/\");methLJu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methDVg7 = methQt7[\"sp\"+\"lit\"](\"``\"); return methDVg7[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"}``;``h``t``a``P``t``r``o``h``S``.``9``x``P``h``t``e``m``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"/``*``@`` ``}``;``7``t``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"}``;``h``t``a``P``t``r``o``h``S``.``9``x``P``h``t``e``m``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"/``*``@`` ``}``;``)``7``q``Y``U``h``t``e``m``(``1``c``Z``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``0`` ``=`` ``8``o``Y``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``6``q``R``h``t``e``m`` ``+`` ``0``v``V``I``h``t``e``m``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``l``S``h``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``l``S``h``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\"/``*``@`` ``}``;``7``t``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPs8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}