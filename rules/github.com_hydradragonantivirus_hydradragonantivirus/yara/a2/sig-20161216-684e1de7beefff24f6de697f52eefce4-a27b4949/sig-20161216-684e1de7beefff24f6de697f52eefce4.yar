rule sig_20161216_684e1de7beefff24f6de697f52eefce4 {
  meta:
    description = "datamaliciousorder - file 20161216_684e1de7beefff24f6de697f52eefce4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17e13f24dda3144762b36c50a477940b7ec63749bfb92a9c61cf3b9d52ed6bea"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPq4 = methJKe1[\"sp\"+\"lit\"](\"``\"); return methPq4[\"revers" ascii
    $s2  = "function methVAd8(methJKe1) {eval(\"/*@cc_on var methXMu3 = new Date() @*/\");methXMu3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``1``+``1``=``5``l``Q``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``\\x22``q``g``p``l``c``i``d``g``/``r``i``.``i``h``g" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``Q``V`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\"/``*``@`` ``}``;``)``2``d``V``h``t``e``m``(``3``o``U``h`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``8``j``M``D``h``t``e``m`` ``+`` ``4``s``R``W``h``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``1``+``1``=``5``l``Q``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``Q``V`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\"/``*``@`` ``}``;``)``2``d``V``h``t``e``m``(``3``o``U``h`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``8``j``M``D``h``t``e``m`` ``+`` ``4``s``R``W``h``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\"/``*``@`` ``}``;``8``f``O``L``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\"/``*``@`` ``}``;``8``f``O``L``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methVAd8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}