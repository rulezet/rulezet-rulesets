rule sig_20161216_c4216b1baa4d3e953f59238f65885c6f {
  meta:
    description = "datamaliciousorder - file 20161216_c4216b1baa4d3e953f59238f65885c6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "522780fd9f03f282dad17350159c752fbe10539506e810dac6e96ff13a0af3ca"

  strings:
    $s1  = "function cheburgenNs4(cheburgenKo8) {eval(\"/*@cc_on var cheburgenMb4 = new Date() @*/\");cheburgenMb4[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenMb4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenTTy6 = cheburgenKo8[\"split\"](\"``\"" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"\")), 1);///////////////////////////////////////////////" ascii
    $s7  = "heburgenTTy6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"/``*``@`` ``}``;``6``y``T``T``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``)``\\x22``\\x22`` ``+`` ``1``i``P``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"/``*``@`` ``}``;``7``h``V``W``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"/``*``@`` ``}``;``8``o``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``1``+``1``=``6``q``R``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``7``b``E``n``e``g``r``u``b``e``h``c`` ``+`` ``2``k``X`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``0`` ``=`` ``9``m``P``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``)``\\x22``y``b``6``g``h``i``9``/``m``o``c``.``n``g``i" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"/``*``@`` ``}``;``)``8``c``E``D``n``e``g``r``u``b``e``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNs4(\";``1``+``1``=``6``q``R``n``e``g``r``u``b``e``h``c`` ``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}