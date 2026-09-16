rule sig_20161216_cd59bc0112765f1aa9aa97d2a7c6d42f {
  meta:
    description = "datamaliciousorder - file 20161216_cd59bc0112765f1aa9aa97d2a7c6d42f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a58b55f89a439978bc63addd1815a03f72f3ce7082ee20f3cd9ac98e4d1cec08"

  strings:
    $s1  = "function cheburgenLx0(cheburgenEk0) {eval(\"/*@cc_on var cheburgenDx3 = new Date() @*/\");cheburgenDx3[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "0\");if (cheburgenDx3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenWt2 = cheburgenEk0[\"split\"](\"``\")" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``0``k``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``9``u``W``R``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``x``J``n`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``\\x22``c``h``c``0``u``o``n``/``r``t``.``m``o``c``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``)``9``d``Z``n``e``g``r``u``b``e``h``c`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``0`` ``=`` ``1``z``X``V``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``6``g``Y``V``n``e``g``r``u``b``e``h``c`` ``+`` ``2``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``0``k``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``1``+``1``=``6``k``H``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``d``Z``n``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``t" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenLx0(\"/``*``@`` ``}``;``9``u``W``R``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}