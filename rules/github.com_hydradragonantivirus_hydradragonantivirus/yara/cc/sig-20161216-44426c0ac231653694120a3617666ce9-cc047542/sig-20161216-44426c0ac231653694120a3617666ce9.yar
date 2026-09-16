rule sig_20161216_44426c0ac231653694120a3617666ce9 {
  meta:
    description = "datamaliciousorder - file 20161216_44426c0ac231653694120a3617666ce9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "190f579188f6123110a2b1dcbf634180c04ba3d61e994d8c65f3d2809d696ad3"

  strings:
    $s1  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methNSm2 = methZVx6[\"sp\"+\"lit\"](\"``\"); return methNSm2[\"reve" ascii
    $s2  = "function methKQa0(methZVx6) {eval(\"/*@cc_on var methLRb8 = new Date() @*/\");methLRb8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``1``+``1``=``7``b``M``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``6``x``V``Z``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``g``X``E``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``0``4``q``B``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``)``1``o``H``h``t``e``m``(``8``i``N``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``2``m``S``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``4``y``L``R``h``t``e``m`` ``+`` ``0``c``R``Q``h``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``2``m``S``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKQa0(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}