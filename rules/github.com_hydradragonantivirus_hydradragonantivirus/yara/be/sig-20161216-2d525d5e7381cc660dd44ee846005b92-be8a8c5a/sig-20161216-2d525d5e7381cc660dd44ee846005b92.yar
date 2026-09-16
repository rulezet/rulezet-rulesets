rule sig_20161216_2d525d5e7381cc660dd44ee846005b92 {
  meta:
    description = "datamaliciousorder - file 20161216_2d525d5e7381cc660dd44ee846005b92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b611856c2c8bd63f936b2827f065c0a156f2ee6e7643ee44efdc5f4db16ea766"

  strings:
    $s1  = "20\");if (cheburgenYs7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEm7 = cheburgenHu9[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenYUv7(cheburgenHu9) {eval(\"/*@cc_on var cheburgenYs7 = new Date() @*/\");cheburgenYs7[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\"/``*``@`` ``}``;``7``m``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``\\x22``g``9``t``o``f``a``p``n``p``/``m``o``c``.``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\"/``*``@`` ``}``;``)``8``p``V``n``e``g``r``u``b``e``h``c" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``s``O``n``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\"/``*``@`` ``}``;``)``8``p``V``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``1``+``1``=``7``a``Q``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s16 = "heburgenEm7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``q``O``E" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``0`` ``=`` ``5``i``G``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYUv7(\";``8``p``H``n``e``g``r``u``b``e``h``c`` ``+`` ``5``r``E" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}