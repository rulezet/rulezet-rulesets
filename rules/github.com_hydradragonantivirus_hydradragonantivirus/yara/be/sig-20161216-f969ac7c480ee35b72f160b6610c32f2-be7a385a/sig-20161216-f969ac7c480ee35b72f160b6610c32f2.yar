rule sig_20161216_f969ac7c480ee35b72f160b6610c32f2 {
  meta:
    description = "datamaliciousorder - file 20161216_f969ac7c480ee35b72f160b6610c32f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed1780e8c61d2aff5aca3d429bbf48875841109cf22abd3996caeb8388e71027"

  strings:
    $s1  = "function methIOv0(methNPn7) {eval(\"/*@cc_on var methZg0 = new Date() @*/\");methZg0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"/``*``@`` ``}``;``4``a``I``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"/``*``@`` ``}``;``0``d``V``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``1``+``1``=``9``c``C``A``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"/``*``@`` ``}``;``)``6``m``M``h``t``e``m``(``4``y``T``h`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"/``*``@`` ``}``;``)``6``m``M``h``t``e``m``(``4``y``T``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``2``k``F``N``h``t``e``m`` ``+`` ``7``v``L``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``q``l``i``y``d``x``u``c``/``t``e``n``.``s``e" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\"}``;``h``t``a``P``t``r``o``h``S``.``8``f``B``S``h``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``m``h``4``5``m``c``1``2``/``m``o``c``.``a``i" ascii
    $s18 = "function methIOv0(methNPn7) {eval(\"/*@cc_on var methZg0 = new Date() @*/\");methZg0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``0`` ``=`` ``1``h``S``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIOv0(\";``)``\\x22``r``3``b``n``f``g``/``m``o``c``.``h``s``i``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}