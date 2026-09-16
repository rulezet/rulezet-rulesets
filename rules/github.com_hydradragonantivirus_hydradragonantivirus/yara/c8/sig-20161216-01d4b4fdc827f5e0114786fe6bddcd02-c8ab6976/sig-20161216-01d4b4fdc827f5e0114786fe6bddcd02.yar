rule sig_20161216_01d4b4fdc827f5e0114786fe6bddcd02 {
  meta:
    description = "datamaliciousorder - file 20161216_01d4b4fdc827f5e0114786fe6bddcd02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "702273210cd973d1ea5a8a7154141692b8821bff7ecea545904411d44ccd5be1"

  strings:
    $s1  = "function cheburgenWPc7(cheburgenRCw8) {eval(\"/*@cc_on var cheburgenGc9 = new Date() @*/\");cheburgenGc9[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``\\x22`` ``+`` ``6``h``H``n``e``g``r``u``b`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``\\x22`` ``+`` ``6``h``H``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\"/``*``@`` ``}``;``4``q``Q``Q``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``" ascii
    $s10 = "n cheburgenZDu4[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``1``+``1``=``1``r``T``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``g``c``w``h``p``/``a``u``.``m``o``c``.``z``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\"/``*``@`` ``}``;``8``w``C``R``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "function cheburgenWPc7(cheburgenRCw8) {eval(\"/*@cc_on var cheburgenGc9 = new Date() @*/\");cheburgenGc9[\"setUTC\"+\"Seconds\"]" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``0``t``W``n``e``g``r``u``b``e``h``c`` ``+`` ``5``f``F" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\"}``;``h``t``a``P``t``r``o``h``S``.``7``t``H``n``e``g``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``0`` ``=`` ``1``i``D``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenWPc7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}