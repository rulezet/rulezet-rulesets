rule sig_20161216_05aa1bbb98d776344d55d5f2d2bab664 {
  meta:
    description = "datamaliciousorder - file 20161216_05aa1bbb98d776344d55d5f2d2bab664.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5f326d216101e62b5d79fd153efe54ec37b4e7752670be1b090a1bc685ba894"

  strings:
    $s1  = "function methOUi7(methFAp4) {eval(\"/*@cc_on var methPd7 = new Date() @*/\");methPd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``0``t``A``h``t``e``m`` ``+`` ``9``c``B``h``t``e``m``=`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``c``R``D``h``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``F``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``1``+``1``=``6``e``T``T``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "etUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methPCr4 = methFAp4[\"sp\"+\"lit\"](\"``\"); return methPCr4[\"reverse" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``z``F``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``a``K``h``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\"/``*``@`` ``}``;``4``r``C``P``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``\\x22``i``d``n``z``z``r``q``q``y``m``/``u``r``.``m" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\";``)``\\x22``g``y``z``o``l``/``l``p``.``s``i``w``r``e``s" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\"}``;``h``t``a``P``t``r``o``h``S``.``3``c``R``D``h``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methOUi7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s20 = "function methOUi7(methFAp4) {eval(\"/*@cc_on var methPd7 = new Date() @*/\");methPd7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}