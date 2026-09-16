rule sig_20161215_0daa98fd8bc7684f64118084979ac67e {
  meta:
    description = "datamaliciousorder - file 20161215_0daa98fd8bc7684f64118084979ac67e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b99e918fb00ef6363a005153aef3c2e83dcb923fc767ae174761f3484f978a41"

  strings:
    $s1  = "function cheburgenEd7(cheburgenEYx5) {eval(\"/*@cc_on var cheburgenOx3 = new Date() @*/\");cheburgenOx3[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenOx3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSn9 = cheburgenEYx5[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\"/``*``@`` ``}``;``8``c``O``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``1``+``1``=``7``z``U``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``1``+``1``=``7``z``U``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\"}``;``h``t``a``P``t``r``o``h``S``.``8``u``Z``n``e``g``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``h``K``B`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``0`` ``=`` ``2``h``A``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\"/``*``@`` ``}``;``5``x``Y``E``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``u" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``2``h``U``D``n``e``g``r``u``b``e``h``c`` ``+`` ``5``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``o" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEd7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}