rule sig_20161215_0dc4d62b124443aa8e8c51f88113aed6 {
  meta:
    description = "datamaliciousorder - file 20161215_0dc4d62b124443aa8e8c51f88113aed6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59e6b5ce4965adc14dfb210f448007bb89829d7307cd2a4afe07a8600d8f9722"

  strings:
    $s1  = "function cheburgenSu3(cheburgenVXr6) {eval(\"/*@cc_on var cheburgenTPf7 = new Date() @*/\");cheburgenTPf7[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``7``z``L``P``n``e``g``r``u``b``e``h``c`` ``+`` ``3``t`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"/``*``@`` ``}``;``4``i``T``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"/``*``@`` ``}``;``4``i``T``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"/``*``@`` ``}``;``6``r``X``V``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``i``X``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``1``+``1``=``4``q``V``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``1``+``1``=``4``q``V``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``z``H``n``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSu3(\";``7``z``L``P``n``e``g``r``u``b``e``h``c`` ``+`` ``3``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}