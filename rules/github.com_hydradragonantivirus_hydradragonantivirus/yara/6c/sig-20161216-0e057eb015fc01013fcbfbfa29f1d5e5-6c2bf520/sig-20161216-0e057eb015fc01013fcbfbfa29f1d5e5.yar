rule sig_20161216_0e057eb015fc01013fcbfbfa29f1d5e5 {
  meta:
    description = "datamaliciousorder - file 20161216_0e057eb015fc01013fcbfbfa29f1d5e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735dd309c8b080ec8dd82ed4ab36593e5834ba821075d7a87edcc2d003577685"

  strings:
    $s1  = "function cheburgenVWe2(cheburgenJSo8) {eval(\"/*@cc_on var cheburgenNBr5 = new Date() @*/\");cheburgenNBr5[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\"/``*``@`` ``}``;``)``1``a``M``L``n``e``g``r``u``b``e``h" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``0`` ``=`` ``7``z``G``M``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\"/``*``@`` ``}``;``4``n``Q``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``e``D``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``1``x``V``B``n``e``g``r``u``b``e``h``c`` ``+`` ``6``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``l``I``H``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``\\x22``\\x22`` ``+`` ``2``t``N``n``e``g``r``u``b`" ascii
    $s16 = "turn cheburgenKLq1[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``e``D``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVWe2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}