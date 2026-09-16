rule sig_20161216_b4dab183833fa1701ae039288caaf663 {
  meta:
    description = "datamaliciousorder - file 20161216_b4dab183833fa1701ae039288caaf663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6ce9618728a14b0a353ac655a05ce1152cdb081204a1f1fb9ac526c20515eab"

  strings:
    $s1  = "function methAPh3(methRs6) {eval(\"/*@cc_on var methEh7 = new Date() @*/\");methEh7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZy8 = methRs6[\"sp\"+\"lit\"](\"``\"); return methZy8[\"reverse\"]()" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"}``;``h``t``a``P``t``r``o``h``S``.``4``g``I``F``h``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``f``S``h``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``0`` ``=`` ``6``c``C``S``h``t``e``m`` ``r``a``v\"))), " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``0`` ``=`` ``6``c``C``S``h``t``e``m`` ``r``a``v\"))), " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``8``y``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``4``z``W``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"}``;``h``t``a``P``t``r``o``h``S``.``4``g``I``F``h``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``6``s``R``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAPh3(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}