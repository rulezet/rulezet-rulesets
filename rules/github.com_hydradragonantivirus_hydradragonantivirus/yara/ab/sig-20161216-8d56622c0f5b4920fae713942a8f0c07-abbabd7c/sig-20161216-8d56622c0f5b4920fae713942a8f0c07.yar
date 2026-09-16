rule sig_20161216_8d56622c0f5b4920fae713942a8f0c07 {
  meta:
    description = "datamaliciousorder - file 20161216_8d56622c0f5b4920fae713942a8f0c07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5779a7162e2bff9bac85110cdeea728c81b3f178914c98d39d7587c0a396fea"

  strings:
    $s1  = "function methBOn3(methVJq9) {eval(\"/*@cc_on var methUt1 = new Date() @*/\");methUt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``9``q``J``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methHJo3 = methVJq9[\"sp\"+\"lit\"](\"``\"); return methHJo3[\"reverse" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``1``+``1``=``7``q``P``T``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``9``q``J``V``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``f``F``h``t`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``3``o``J``H``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``s``O``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``0`` ``=`` ``0``e``Y``G``h``t``e``m`` ``r``a``v\"))), " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``8``k``U``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``0``b``L``h``t``e``m`` ``+`` ``7``d``O``O``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\"/``*``@`` ``}``;``)``0``f``B``h``t``e``m``(``8``d``Y``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methBOn3(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}