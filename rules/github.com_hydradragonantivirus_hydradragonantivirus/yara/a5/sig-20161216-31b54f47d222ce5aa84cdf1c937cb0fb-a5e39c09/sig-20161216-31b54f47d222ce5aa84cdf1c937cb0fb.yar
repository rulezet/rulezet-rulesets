rule sig_20161216_31b54f47d222ce5aa84cdf1c937cb0fb {
  meta:
    description = "datamaliciousorder - file 20161216_31b54f47d222ce5aa84cdf1c937cb0fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f356e4a24c4309cae4e132ab936b8e364ac5a37f77ee1991e44bee1992c24dfd"

  strings:
    $s1  = "function methWEz0(methYe4) {eval(\"/*@cc_on var methZJt1 = new Date() @*/\");methZJt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPUc6 = methYe4[\"sp\"+\"lit\"](\"``\"); return methPUc6[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"/``*``@`` ``}``;``6``c``U``P``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``u``Q``h``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"/``*``@`` ``}``;``3``o``Q``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"/``*``@`` ``}``;``4``e``Y``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``0`` ``=`` ``6``l``U``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``1``f``Z``H``h``t``e``m`` ``+`` ``8``x``W``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWEz0(\";``0`` ``=`` ``6``l``U``h``t``e``m`` ``r``a``v\"))), 1);" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}