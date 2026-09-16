rule sig_20161216_2012863dea1605a0f5a3769952574b9c {
  meta:
    description = "datamaliciousorder - file 20161216_2012863dea1605a0f5a3769952574b9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cd67712fe6b878da90a5d48283cf245b290579d337fef59c250af20e403abb2"

  strings:
    $s1  = "function cheburgenTv9(cheburgenJEx7) {eval(\"/*@cc_on var cheburgenRr2 = new Date() @*/\");cheburgenRr2[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenRr2[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenPi9 = cheburgenJEx7[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``e``S``n``e``g``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``n``L``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``0`` ``=`` ``5``p``W``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"/``*``@`` ``}``;``9``i``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``3``b``D``n``e``g``r``u``b``e``h``c`` ``+`` ``7``v``T`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"/``*``@`` ``}``;``8``o``X``P``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"/``*``@`` ``}``;``)``7``e``P``n``e``g``r``u``b``e``h``c`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``e``S``n``e``g``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``1``+``1``=``8``k``X``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "cheburgenPi9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenTv9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}