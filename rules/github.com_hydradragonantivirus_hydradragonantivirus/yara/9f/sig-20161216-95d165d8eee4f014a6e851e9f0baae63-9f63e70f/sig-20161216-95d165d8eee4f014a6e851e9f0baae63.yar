rule sig_20161216_95d165d8eee4f014a6e851e9f0baae63 {
  meta:
    description = "datamaliciousorder - file 20161216_95d165d8eee4f014a6e851e9f0baae63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aabb65a05ae1d08e414bdf7b2529eb93941857e0b18d2e220834ff0d5dee35f9"

  strings:
    $s1  = "function cheburgenFk0(cheburgenZl4) {eval(\"/*@cc_on var cheburgenOBi2 = new Date() @*/\");cheburgenOBi2[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\"/``*``@`` ``}``;``4``l``Z``n``e``g``r``u``b``e``h``c`` `" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``f``Y``T`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\"}``;``h``t``a``P``t``r``o``h``S``.``5``i``T``C``n``e``g`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``." ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``b``V``n``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s14 = "n cheburgenFWt7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``f``Y``T`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``0`` ``=`` ``1``e``W``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\";``1``+``1``=``6``y``P``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "function cheburgenFk0(cheburgenZl4) {eval(\"/*@cc_on var cheburgenOBi2 = new Date() @*/\");cheburgenOBi2[\"setUTC\"+\"Seconds\"]" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFk0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}