rule sig_20161216_e63857d40c6dbf0f8edd373e6cede650 {
  meta:
    description = "datamaliciousorder - file 20161216_e63857d40c6dbf0f8edd373e6cede650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2d8983fd4ca5bc3f0b88ec08cdc5deb8a1d2c6f9ab435ec610ab233b580dcbe"

  strings:
    $s1  = "20\");if (cheburgenMw6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenHc7 = cheburgenRYx8[\"split\"](\"``" ascii
    $s2  = "function cheburgenTi7(cheburgenRYx8) {eval(\"/*@cc_on var cheburgenMw6 = new Date() @*/\");cheburgenMw6[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``g``9``t``o``f``a``p``n``p``/``m``o``c``.``s" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\"/``*``@`` ``}``;``1``t``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``v" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``g``c``w``h``p``/``a``u``.``m``o``c``.``z``a" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``\\x22`` ``+`` ``7``x``G``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\"/``*``@`` ``}``;``1``t``B``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``1``+``1``=``9``g``X``Z``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``0`` ``=`` ``0``j``A``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``2``x``U``n``e``g``r``u``b``e``h``c`` ``+`` ``3``r``A`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``0`` ``=`` ``0``j``A``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "function cheburgenTi7(cheburgenRYx8) {eval(\"/*@cc_on var cheburgenMw6 = new Date() @*/\");cheburgenMw6[\"setUTC\"+\"Seconds\"](" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\";``)``\\x22``\\x22`` ``+`` ``7``x``G``n``e``g``r``u``b``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTi7(\"}``;``h``t``a``P``t``r``o``h``S``.``2``g``Q``n``e``g``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}