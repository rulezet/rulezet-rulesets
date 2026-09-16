rule sig_20161215_5b77d9229485e76f55a1d39bf579a883 {
  meta:
    description = "datamaliciousorder - file 20161215_5b77d9229485e76f55a1d39bf579a883.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "286267448c5430015a464d8761d162dddcd9b98c82978fc1c530e6b9899fea7a"

  strings:
    $s1  = "20\");if (cheburgenFi9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSZs9 = cheburgenTg7[\"split\"](\"``" ascii
    $s2  = "function cheburgenYMa2(cheburgenTg7) {eval(\"/*@cc_on var cheburgenFi9 = new Date() @*/\");cheburgenFi9[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"/``*``@`` ``}``;``0``y``D``G``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``y``Z``H" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"/``*``@`` ``}``;``9``s``Z``S``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``5``d``D``H``n``e``g``r``u``b``e``h``c`` ``+`` ``4``j" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``0`` ``=`` ``1``b``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``1``+``1``=``8``v``T``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"/``*``@`` ``}``;``7``g``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``)``\\x22``\\x22`` ``+`` ``8``q``B``A``n``e``g``r``u`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``5``d``D``H``n``e``g``r``u``b``e``h``c`` ``+`` ``4``j" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``)``\\x22``7``p``j``7``o``t``/``a``c``.``p``r``o``c``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"/``*``@`` ``}``;``)``1``s``L``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``)``\\x22``7``p``j``7``o``t``/``a``c``.``p``r``o``c``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYMa2(\";``0`` ``=`` ``1``b``I``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}