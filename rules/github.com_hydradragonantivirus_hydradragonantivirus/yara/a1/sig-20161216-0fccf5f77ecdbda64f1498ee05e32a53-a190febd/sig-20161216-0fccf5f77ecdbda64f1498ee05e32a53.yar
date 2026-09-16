rule sig_20161216_0fccf5f77ecdbda64f1498ee05e32a53 {
  meta:
    description = "datamaliciousorder - file 20161216_0fccf5f77ecdbda64f1498ee05e32a53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e630d1ea33106f36e908f7102eb43ffe1f428f01106bcc56246ac33594e41cf1"

  strings:
    $s1  = "function cheburgenWJn0(cheburgenOKw0) {eval(\"/*@cc_on var cheburgenQx3 = new Date() @*/\");cheburgenQx3[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenQx3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenTm2 = cheburgenOKw0[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``1``+``1``=``2``f``M``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``0`` ``=`` ``9``b``C``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s10 = "function cheburgenWJn0(cheburgenOKw0) {eval(\"/*@cc_on var cheburgenQx3 = new Date() @*/\");cheburgenQx3[\"setUTC\"+\"Seconds\"]" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\"/``*``@`` ``}``;``0``w``K``O``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``1``+``1``=``2``f``M``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``0`` ``=`` ``9``b``C``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = " cheburgenTm2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\"/``*``@`` ``}``;``)``2``t``G``B``n``e``g``r``u``b``e``h" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``d``B``X``n" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWJn0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}