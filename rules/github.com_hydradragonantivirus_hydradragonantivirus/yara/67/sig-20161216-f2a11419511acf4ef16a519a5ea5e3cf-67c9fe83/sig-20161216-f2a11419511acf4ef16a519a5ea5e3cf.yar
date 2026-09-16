rule sig_20161216_f2a11419511acf4ef16a519a5ea5e3cf {
  meta:
    description = "datamaliciousorder - file 20161216_f2a11419511acf4ef16a519a5ea5e3cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84a61208f8624c559e1278bab7cbffed09fc1687fdf34013ead714504e007001"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUQr3 = methLh6[\"sp\"+\"lit\"](\"``\"); return methUQr3[\"revers" ascii
    $s2  = "function methNWq9(methLh6) {eval(\"/*@cc_on var methQFu1 = new Date() @*/\");methQFu1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\"/``*``@`` ``}``;``3``r``Q``U``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``5``q``W``h``t``e``m`` ``+`` ``0``m``X``B``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\"/``*``@`` ``}``;``2``b``D``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\"}``;``h``t``a``P``t``r``o``h``S``.``0``b``W``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNWq9(\";``0`` ``=`` ``0``l``I``J``h``t``e``m`` ``r``a``v\"))), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}