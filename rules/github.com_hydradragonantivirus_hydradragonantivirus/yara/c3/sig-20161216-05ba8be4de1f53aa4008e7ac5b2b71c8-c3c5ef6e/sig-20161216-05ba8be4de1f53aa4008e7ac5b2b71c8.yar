rule sig_20161216_05ba8be4de1f53aa4008e7ac5b2b71c8 {
  meta:
    description = "datamaliciousorder - file 20161216_05ba8be4de1f53aa4008e7ac5b2b71c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a05cbf43e2ed96a993fed9ffa00f5c28bdb1a1ed05104172b95dff585cd3cc11"

  strings:
    $s1  = "function cheburgenUz8(cheburgenELr5) {eval(\"/*@cc_on var cheburgenUq3 = new Date() @*/\");cheburgenUq3[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenUq3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenGRg3 = cheburgenELr5[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``g``B``L``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``3``g``R``G``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``8``k``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"}``;``h``t``a``P``t``r``o``h``S``.``5``w``U``E``n``e``g`" ascii
    $s7  = "function cheburgenUz8(cheburgenELr5) {eval(\"/*@cc_on var cheburgenUq3 = new Date() @*/\");cheburgenUq3[\"setUTC\"+\"Seconds\"](" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``)``\\x22``\\x22`` ``+`` ``3``b``A``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``g``B``L``n`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``)``4``g``O``J``n``e``g``r``u``b``e``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``0`` ``=`` ``0``v``H``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"\")), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"}``;``h``t``a``P``t``r``o``h``S``.``5``w``U``E``n``e``g`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUz8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}