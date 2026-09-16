rule sig_20161216_ec671f2aa3955f887429afb0f71d6e98 {
  meta:
    description = "datamaliciousorder - file 20161216_ec671f2aa3955f887429afb0f71d6e98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8fd9295ea7c93f9944a5f53f5927045b40db4ce5985dbca323bab7148ea62e6"

  strings:
    $s1  = "function cheburgenSl1(cheburgenWt2) {eval(\"/*@cc_on var cheburgenOl6 = new Date() @*/\");cheburgenOl6[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenOl6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenRs6 = cheburgenWt2[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\"/``*``@`` ``}``;``6``s``R``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\"/``*``@`` ``}``;``)``8``y``O``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``\\x22`` ``+`` ``6``v``E``D``n``e``g``r``u``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\"\")), 1);///////////////////////////////////////////////" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``0`` ``=`` ``3``f``M``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\"/``*``@`` ``}``;``)``8``y``O``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``1``+``1``=``7``w``M``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``c``T``n``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``0`` ``=`` ``3``f``M``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenSl1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}