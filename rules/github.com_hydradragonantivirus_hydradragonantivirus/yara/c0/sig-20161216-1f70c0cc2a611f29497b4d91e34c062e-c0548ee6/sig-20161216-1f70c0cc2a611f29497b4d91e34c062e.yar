rule sig_20161216_1f70c0cc2a611f29497b4d91e34c062e {
  meta:
    description = "datamaliciousorder - file 20161216_1f70c0cc2a611f29497b4d91e34c062e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34f008eea2de61523b7af96f1e61891583f1f25519c882ba017548f38a787948"

  strings:
    $s1  = "function cheburgenIo3(cheburgenXh1) {eval(\"/*@cc_on var cheburgenCWh5 = new Date() @*/\");cheburgenCWh5[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``)``\\x22``\\x22`` ``+`` ``4``m``H``T``n``e``g``r``u``" ascii
    $s3  = "function cheburgenIo3(cheburgenXh1) {eval(\"/*@cc_on var cheburgenCWh5 = new Date() @*/\");cheburgenCWh5[\"setUTC\"+\"Seconds\"]" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"/``*``@`` ``}``;``2``h``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``1``+``1``=``6``u``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"/``*``@`` ``}``;``)``6``a``F``D``n``e``g``r``u``b``e``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``1``n``P``n``e``g``r``u``b``e``h``c`` ``+`` ``7``n``K`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``1``+``1``=``6``u``E``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"/``*``@`` ``}``;``1``h``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``h``A``F``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``)``\\x22``n``x``g``k``q``n``j``3``o``u``/``r``t``.``l" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"/``*``@`` ``}``;``6``r``E``J``n``e``g``r``u``b``e``h``c`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"}``;``h``t``a``P``t``r``o``h``S``.``5``y``Z``n``e``g``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIo3(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}