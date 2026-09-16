rule sig_20161215_d97e7b980e6f1a3eae79d759146e002a {
  meta:
    description = "datamaliciousorder - file 20161215_d97e7b980e6f1a3eae79d759146e002a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7323c39d90e174ff90b2d53bfdf8e5990ae27bbde5eb9a3db74008c45bbb1fe"

  strings:
    $s1  = "\"20\");if (cheburgenEMv5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenLn9 = cheburgenOn9[\"split\"](\"`" ascii
    $s2  = "function cheburgenCf1(cheburgenOn9) {eval(\"/*@cc_on var cheburgenEMv5 = new Date() @*/\");cheburgenEMv5[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``)``6``z``O``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``)``\\x22``\\x22`` ``+`` ``1``w``D``B``n``e``g``r``u``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``5``m``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``1``g``V``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``7``f`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``h``W``n``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``h``W``n``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``L``n``e``g``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``9``n``L``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\";``0`` ``=`` ``2``l``V``Y``n``e``g``r``u``b``e``h``c`` `" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"/``*``@`` ``}``;``9``n``O``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCf1(\"\")), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}