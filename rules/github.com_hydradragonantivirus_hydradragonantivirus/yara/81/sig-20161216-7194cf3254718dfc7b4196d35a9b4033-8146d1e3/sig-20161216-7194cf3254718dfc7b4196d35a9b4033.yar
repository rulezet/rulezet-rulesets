rule sig_20161216_7194cf3254718dfc7b4196d35a9b4033 {
  meta:
    description = "datamaliciousorder - file 20161216_7194cf3254718dfc7b4196d35a9b4033.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa40e3d41d14b0149b9b902800460009ce7579f9c6bba7608a336a2495c5548"

  strings:
    $s1  = "function methCIq1(methQDb5) {eval(\"/*@cc_on var methZa6 = new Date() @*/\");methZa6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``3``m``Q``I``h``t``e``m`` ``+`` ``3``g``L``D``h``t``e`" ascii
    $s3  = "function methCIq1(methQDb5) {eval(\"/*@cc_on var methZa6 = new Date() @*/\");methZa6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"/``*``@`` ``}``;``5``b``D``Q``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"/``*``@`` ``}``;``1``e``F``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"/``*``@`` ``}``;``)``1``p``K``I``h``t``e``m``(``8``d``V`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``o``A``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``1``+``1``=``4``p``R``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``\\x22``g``f``u``g``0``/``m``o``c``.``t``j``t``j``l" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``\\x22``p``i``d``1``e``1``/``e``d``.``r``e``d``n``i" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``3``m``Q``I``h``t``e``m`` ``+`` ``3``g``L``D``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\"/``*``@`` ``}``;``)``1``p``K``I``h``t``e``m``(``8``d``V`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCIq1(\";``1``+``1``=``4``p``R``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}