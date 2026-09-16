rule sig_20161216_7e6994af1be286b32be7381bc7f57748 {
  meta:
    description = "datamaliciousorder - file 20161216_7e6994af1be286b32be7381bc7f57748.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8bb579d53acfdb2c1405827e75db4888bc1ef374096b827ea590ae75235fde4"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNGi7 = methJs9[\"sp\"+\"lit\"](\"``\"); return methNGi7[\"revers" ascii
    $s2  = "function methTLf2(methJs9) {eval(\"/*@cc_on var methKFf1 = new Date() @*/\");methKFf1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``p``Q``D`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``9``s``J``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``D``h``t``e``m`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``z``K``Y``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``7``i``G``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``1``+``1``=``7``e``E``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``)``7``j``K``h``t``e``m``(``2``y``D``C`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``0`` ``=`` ``6``g``K``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"}``;``h``t``a``P``t``r``o``h``S``.``2``e``D``h``t``e``m`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``p``Q``D`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTLf2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}