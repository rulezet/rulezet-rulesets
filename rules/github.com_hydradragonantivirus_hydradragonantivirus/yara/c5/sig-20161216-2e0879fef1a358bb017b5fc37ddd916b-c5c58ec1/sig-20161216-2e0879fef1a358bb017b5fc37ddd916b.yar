rule sig_20161216_2e0879fef1a358bb017b5fc37ddd916b {
  meta:
    description = "datamaliciousorder - file 20161216_2e0879fef1a358bb017b5fc37ddd916b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6bf0c038d34e3f64f8720767949125b8c9d221e7f8902da6ac68c831194ab1b"

  strings:
    $s1  = "0\");if (cheburgenDc7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNd5 = cheburgenUz1[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenLd4(cheburgenUz1) {eval(\"/*@cc_on var cheburgenDc7 = new Date() @*/\");cheburgenDc7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``x``N``H``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\"\")), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``0`` ``=`` ``5``c``B``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``x``N``H``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\"/``*``@`` ``}``;``1``z``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``m``e``k``k``8``u``o``/``m``o``c``.``s``n``o" ascii
    $s14 = "eburgenNd5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "function cheburgenLd4(cheburgenUz1) {eval(\"/*@cc_on var cheburgenDc7 = new Date() @*/\");cheburgenDc7[\"setUTC\"+\"Seconds\"](" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``\\x22`` ``+`` ``8``h``D``n``e``g``r``u``b``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``0`` ``=`` ``5``c``B``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLd4(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}