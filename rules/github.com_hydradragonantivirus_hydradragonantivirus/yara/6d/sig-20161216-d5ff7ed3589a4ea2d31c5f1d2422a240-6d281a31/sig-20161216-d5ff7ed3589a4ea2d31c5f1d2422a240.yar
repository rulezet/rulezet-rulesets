rule sig_20161216_d5ff7ed3589a4ea2d31c5f1d2422a240 {
  meta:
    description = "datamaliciousorder - file 20161216_d5ff7ed3589a4ea2d31c5f1d2422a240.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "844c0dc100dd50980fea3a3e68a51ccbdd0f547d51801cd5ce6933f6436cb437"

  strings:
    $s1  = "function methXt0(methYTn5) {eval(\"/*@cc_on var methTs0 = new Date() @*/\");methTs0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``n``Q``h``t``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``i``p``m``n``u``r``d``9``/``m``o``c``.``g``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``4``m``e``j``f``/``a``b``.``m``o``c``.``n``o`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``a``C``C``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii
    $s8  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUQf1 = methYTn5[\"sp\"+\"lit\"](\"``\"); return methUQf1[\"reverse\"" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``)``1``f``C``G``h``t``e``m``(``0``t``D``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``0`` ``=`` ``3``n``M``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``1``f``Q``U``h``t``e``m`` ``n``r``u``t``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\"/``*``@`` ``}``;``7``l``Q``F``h``t``e``m`` ``n``r``u``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXt0(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``.`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}