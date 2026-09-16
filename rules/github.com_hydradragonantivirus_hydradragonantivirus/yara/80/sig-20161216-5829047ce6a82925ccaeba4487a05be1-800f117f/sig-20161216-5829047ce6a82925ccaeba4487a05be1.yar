rule sig_20161216_5829047ce6a82925ccaeba4487a05be1 {
  meta:
    description = "datamaliciousorder - file 20161216_5829047ce6a82925ccaeba4487a05be1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "278f4282087b58dcd26456afe912745e82753f1252afb0f0c51ff32fbf5ddab0"

  strings:
    $s1  = "function methGq0(methPNq1) {eval(\"/*@cc_on var methLb7 = new Date() @*/\");methLb7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``B``O``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``0`` ``=`` ``0``r``O``X``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``B``O``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``i``Z``h``t``e``m``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``g``E``h``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``7``x``I``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``)``0``d``T``K``h``t``e``m``(``9``u``A``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``1``q``N``P``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``7``g``N``C``h``t``e``m`` ``+`` ``8``a``Z``H``h``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\"/``*``@`` ``}``;``1``q``N``P``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methGq0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}