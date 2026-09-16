rule sig_20161216_875e309d46cd78550db4d7adb1682221 {
  meta:
    description = "datamaliciousorder - file 20161216_875e309d46cd78550db4d7adb1682221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49b5ab1928b69b03827cef778ac58723fbed167e06023f78e66d584323912780"

  strings:
    $s1  = "0\");if (cheburgenCs4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenYm4 = cheburgenHr9[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenLz0(cheburgenHr9) {eval(\"/*@cc_on var cheburgenCs4 = new Date() @*/\");cheburgenCs4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``0`` ``=`` ``0``j``G``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``7``o``H``n``e``g``r``u``b``e``h``c`` ``+`` ``1``w``V`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\"/``*``@`` ``}``;``9``r``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``T``R`" ascii
    $s7  = "eburgenYm4[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``\\x22``\\x22`` ``+`` ``5``d``G``n``e``g``r``u``b``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\"/``*``@`` ``}``;``9``r``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``1``+``1``=``1``z``T``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\"/``*``@`` ``}``;``8``e``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``\\x22``\\x22`` ``+`` ``5``d``G``n``e``g``r``u``b``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``v``T``R`" ascii
    $s16 = "function cheburgenLz0(cheburgenHr9) {eval(\"/*@cc_on var cheburgenCs4 = new Date() @*/\");cheburgenCs4[\"setUTC\"+\"Seconds\"](" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\"/``*``@`` ``}``;``)``5``o``K``Z``n``e``g``r``u``b``e``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\"/``*``@`` ``}``;``)``5``o``K``Z``n``e``g``r``u``b``e``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLz0(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}