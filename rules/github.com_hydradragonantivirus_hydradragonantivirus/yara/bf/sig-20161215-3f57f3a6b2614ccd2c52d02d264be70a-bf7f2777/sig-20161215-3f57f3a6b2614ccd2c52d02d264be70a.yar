rule sig_20161215_3f57f3a6b2614ccd2c52d02d264be70a {
  meta:
    description = "datamaliciousorder - file 20161215_3f57f3a6b2614ccd2c52d02d264be70a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3b87f2dce4f1d1506f9f59897e61cee2f354da8663b959a9a8c518339c545c2"

  strings:
    $s1  = "\"20\");if (cheburgenBEt3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenAx6 = cheburgenSi4[\"split\"](\"`" ascii
    $s2  = "function cheburgenVl8(cheburgenSi4) {eval(\"/*@cc_on var cheburgenBEt3 = new Date() @*/\");cheburgenBEt3[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"/``*``@`` ``}``;``6``x``A``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``r``X``n``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"/``*``@`` ``}``;``7``r``S``V``n``e``g``r``u``b``e``h``c`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``g``L``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``o``b``q``q``z``v``h``d``/``u``r``.``5``t``s" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"\")), 1);///////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``1``+``1``=``9``p``A``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``\\x22`` ``+`` ``3``n``W``E``n``e``g``r``u``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``1``+``1``=``9``p``A``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVl8(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}