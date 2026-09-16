rule sig_20161216_e570dd95a13dfc5f61ab3bf4e6910ea8 {
  meta:
    description = "datamaliciousorder - file 20161216_e570dd95a13dfc5f61ab3bf4e6910ea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9105f7558183e2324b4162ced135439fe1810b55e0f5bae6bf2a6e8363c401"

  strings:
    $s1  = "function cheburgenCy7(cheburgenYv2) {eval(\"/*@cc_on var cheburgenZCk1 = new Date() @*/\");cheburgenZCk1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenZCk1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenHq1 = cheburgenYv2[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\"/``*``@`` ``}``;``1``x``J``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``0`` ``=`` ``0``b``Z``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``\\x22``\\x22`` ``+`` ``4``z``W``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``1``+``1``=``7``q``D``M``n``e``g``r``u``b``e``h``c`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\"/``*``@`` ``}``;``1``q``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``\\x22``d``q``j``4``d``u``/``m``o``c``.``d``n``a``l" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\"/``*``@`` ``}``;``1``x``J``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenCy7(\";``1``+``1``=``7``q``D``M``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}