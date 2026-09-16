rule sig_20161215_b1c6cc94e7372a1248f430891ed4d6a5 {
  meta:
    description = "datamaliciousorder - file 20161215_b1c6cc94e7372a1248f430891ed4d6a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b743dafa8c30f879dbe137d290ad2a82505f795eb5d579c4a18d26c459f9a686"

  strings:
    $s1  = "20\");if (cheburgenDw0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAv7 = cheburgenNw4[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenSVn3(cheburgenNw4) {eval(\"/*@cc_on var cheburgenDw0 = new Date() @*/\");cheburgenDw0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``9``p``S``n``e``g``r``u``b``e``h``c`` ``+`` ``5``t``D" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``\\x22``p``e``t``f``1``e``8``u``o``/``t``i``.``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``\\x22``\\x22`` ``+`` ``3``s``I``n``e``g``r``u``b`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``v``J``n``e``g``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\"/``*``@`` ``}``;``7``v``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``g``I``n``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``f``J``n" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSVn3(\"/``*``@`` ``}``;``4``w``N``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}