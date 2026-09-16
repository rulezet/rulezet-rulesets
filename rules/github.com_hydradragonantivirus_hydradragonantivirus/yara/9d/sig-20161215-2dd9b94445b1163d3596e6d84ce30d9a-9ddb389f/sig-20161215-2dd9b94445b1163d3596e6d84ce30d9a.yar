rule sig_20161215_2dd9b94445b1163d3596e6d84ce30d9a {
  meta:
    description = "datamaliciousorder - file 20161215_2dd9b94445b1163d3596e6d84ce30d9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f245a0fb7a2209cf14f81f055bbd8b6a3d6c27fdaa996f5754b000ecb1b77dd6"

  strings:
    $s1  = "\"20\");if (cheburgenVQj9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFx4 = cheburgenUg0[\"split\"](\"`" ascii
    $s2  = "function cheburgenFm2(cheburgenUg0) {eval(\"/*@cc_on var cheburgenVQj9 = new Date() @*/\");cheburgenVQj9[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``0`` ``=`` ``9``r``M``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``)``\\x22``c``g``r``n``t``c``4``q``q``/``m``o``c``.``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"/``*``@`` ``}``;``)``8``f``K``F``n``e``g``r``u``b``e``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"}``;``h``t``a``P``t``r``o``h``S``.``0``p``C``H``n``e``g`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``1``+``1``=``0``s``P``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"/``*``@`` ``}``;``)``8``f``K``F``n``e``g``r``u``b``e``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``1``+``1``=``0``s``P``K``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``u``Z``n`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``a``V``n``e`" ascii
    $s15 = "function cheburgenFm2(cheburgenUg0) {eval(\"/*@cc_on var cheburgenVQj9 = new Date() @*/\");cheburgenVQj9[\"setUTC\"+\"Seconds\"]" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"/``*``@`` ``}``;``0``g``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\"/``*``@`` ``}``;``7``p``G``P``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``0`` ``=`` ``9``r``M``I``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFm2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}