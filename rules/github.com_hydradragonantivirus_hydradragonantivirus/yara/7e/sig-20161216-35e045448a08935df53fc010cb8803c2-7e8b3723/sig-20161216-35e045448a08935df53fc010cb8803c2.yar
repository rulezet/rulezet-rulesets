rule sig_20161216_35e045448a08935df53fc010cb8803c2 {
  meta:
    description = "datamaliciousorder - file 20161216_35e045448a08935df53fc010cb8803c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e213d9a6a5f24b849bce00f378ddf538ab874599dd00efcfbbaff9af3f730b5"

  strings:
    $s1  = "20\");if (cheburgenYn0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNTy6 = cheburgenQb8[\"split\"](\"``" ascii
    $s2  = "function cheburgenJEt7(cheburgenQb8) {eval(\"/*@cc_on var cheburgenYn0 = new Date() @*/\");cheburgenYn0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "function cheburgenJEt7(cheburgenQb8) {eval(\"/*@cc_on var cheburgenYn0 = new Date() @*/\");cheburgenYn0[\"setUTC\"+\"Seconds\"](" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``\\x22`` ``+`` ``2``i``D``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\"/``*``@`` ``}``;``8``b``Q``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``1``+``1``=``1``o``F``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``i``A``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``i``A``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\"}``;``h``t``a``P``t``r``o``h``S``.``4``w``O``N``n``e``g" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\"/``*``@`` ``}``;``6``y``T``N``n``e``g``r``u``b``e``h``c" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\"/``*``@`` ``}``;``3``o``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJEt7(\"/``*``@`` ``}``;``6``y``T``N``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}