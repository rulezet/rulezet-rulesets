rule sig_20161216_128e0b4bfb07fee12f537521b0234ca2 {
  meta:
    description = "datamaliciousorder - file 20161216_128e0b4bfb07fee12f537521b0234ca2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d348e6d82431f80bc25e41ada4d67a22bb7af813da303e145f6617dddffc74"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methQv0 = methRq8[\"sp\"+\"lit\"](\"``\"); return methQv0[\"reverse\"]" ascii
    $s2  = "function methAq9(methRq8) {eval(\"/*@cc_on var methVPu2 = new Date() @*/\");methVPu2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``0`` ``=`` ``5``a``Z``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``j``L``h``t``e``m``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``4``a``D``J``h``t``e``m`` ``n``r``u``t``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``a``V``M``h``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``8``q``R``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``x``A``P``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"}``;``h``t``a``P``t``r``o``h``S``.``7``j``L``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``4``j``Y``h``t``e``m`` ``+`` ``9``l``B``A``h``t``e``m``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``)``3``e``F``h``t``e``m``(``4``g``F``N``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``0`` ``=`` ``5``a``Z``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\"/``*``@`` ``}``;``)``3``e``F``h``t``e``m``(``4``g``F``N``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``x``A``P``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAq9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}