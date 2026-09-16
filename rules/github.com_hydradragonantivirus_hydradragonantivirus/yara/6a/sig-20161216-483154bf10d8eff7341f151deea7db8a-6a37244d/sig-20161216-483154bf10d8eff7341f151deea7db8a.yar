rule sig_20161216_483154bf10d8eff7341f151deea7db8a {
  meta:
    description = "datamaliciousorder - file 20161216_483154bf10d8eff7341f151deea7db8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd2f1295efbc99d7d3eee495ae148692338fd95122dbef7a9e0b409c8dff0e22"

  strings:
    $s1  = "20\");if (cheburgenEx0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOg5 = cheburgenRl6[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenAFl9(cheburgenRl6) {eval(\"/*@cc_on var cheburgenEx0 = new Date() @*/\");cheburgenEx0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``)``0``g``A``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``5``g``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``6``l``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``d``O``V``n``e``g" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``5``g``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``\\x22``\\x22`` ``+`` ``6``u``E``B``n``e``g``r``u`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``6``l``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``)``0``g``A``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"/``*``@`` ``}``;``0``m``I``W``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "heburgenOg5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``1``+``1``=``1``u``M``I``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAFl9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``q``K``N" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}