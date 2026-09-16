rule sig_20161216_b2c850791f0999131c3cc59d941327a5 {
  meta:
    description = "datamaliciousorder - file 20161216_b2c850791f0999131c3cc59d941327a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4bd3234bf266f7319c1a0970cf6c6e50256eb2ec9f92de69ba4ab18af7c07f7"

  strings:
    $s1  = "function cheburgenFWl3(cheburgenTx6) {eval(\"/*@cc_on var cheburgenVAq9 = new Date() @*/\");cheburgenVAq9[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\"/``*``@`` ``}``;``6``x``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``x``F``X" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``0`` ``=`` ``9``j``D``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``1``+``1``=``2``g``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s14 = "n cheburgenPv5[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``3``x``V``L``n``e``g``r``u``b``e``h``c`` ``+`` ``7``b" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``\\x22``\\x22`` ``+`` ``3``o``C``F``n``e``g``r``u`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\"/``*``@`` ``}``;``)``4``k``R``X``n``e``g``r``u``b``e``h" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``x``F``X" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenFWl3(\"/``*``@`` ``}``;``5``v``P``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}