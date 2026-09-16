rule sig_20161216_cb971afa95756f40ddda4118d15b640d {
  meta:
    description = "datamaliciousorder - file 20161216_cb971afa95756f40ddda4118d15b640d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0409b810ef5b106ffe7681c5a9640256a00c2c378868dacd521c0f6dc0f3530"

  strings:
    $s1  = "function cheburgenQJo8(cheburgenEHw7) {eval(\"/*@cc_on var cheburgenDn6 = new Date() @*/\");cheburgenDn6[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"}``;``h``t``a``P``t``r``o``h``S``.``1``u``L``n``e``g``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``)``\\x22``\\x22`` ``+`` ``6``o``W``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``s``D``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``0`` ``=`` ``4``b``H``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``7``m``B``N``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``)``3``z``B``U``n``e``g``r``u``b``e``h" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``5``k``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``v``B``n``e" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``v``B``n``e" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``1``+``1``=``6``r``Q``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "n cheburgenNBm7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``5``k``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\";``0`` ``=`` ``4``b``H``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQJo8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}