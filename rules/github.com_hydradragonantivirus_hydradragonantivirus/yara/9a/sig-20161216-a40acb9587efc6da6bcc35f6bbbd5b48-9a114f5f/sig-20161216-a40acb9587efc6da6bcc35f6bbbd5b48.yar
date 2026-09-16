rule sig_20161216_a40acb9587efc6da6bcc35f6bbbd5b48 {
  meta:
    description = "datamaliciousorder - file 20161216_a40acb9587efc6da6bcc35f6bbbd5b48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41b96af18399c5c1a917750abc09f45ad5f90819037a9e2729fdafb38fa7641e"

  strings:
    $s1  = "function methACx8(methDKu2) {eval(\"/*@cc_on var methDp3 = new Date() @*/\");methDp3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"/``*``@`` ``}``;``)``5``f``N``P``h``t``e``m``(``3``j``H`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``1``+``1``=``4``k``J``I``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"/``*``@`` ``}``;``5``p``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "function methACx8(methDKu2) {eval(\"/*@cc_on var methDp3 = new Date() @*/\");methDp3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``8``v``H``B``h``t``e``m`` ``+`` ``9``n``U``G``h``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"/``*``@`` ``}``;``5``p``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``k``B``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"/``*``@`` ``}``;``4``g``N``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``0`` ``=`` ``3``u``F``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\"/``*``@`` ``}``;``2``u``K``D``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methACx8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}