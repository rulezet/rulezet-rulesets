rule sig_20161216_68d312ffe2615f6b6ce7a91747eb744e {
  meta:
    description = "datamaliciousorder - file 20161216_68d312ffe2615f6b6ce7a91747eb744e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c339202c4f179673bdb1fdcc12b8f5961777e6fae8f74e5edbd747477dc479f6"

  strings:
    $s1  = "function methMMy4(methJr8) {eval(\"/*@cc_on var methSv2 = new Date() @*/\");methSv2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``1``+``1``=``2``u``R``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``\\x22``u``t``o``w``i``u``0``v``/``u``r``.``r``a``c" ascii
    $s4  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methCLz5 = methJr8[\"sp\"+\"lit\"](\"``\"); return methCLz5[\"reverse\"]" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``8``r``J``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``x``W``Q``h``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"}``;``h``t``a``P``t``r``o``h``S``.``3``x``W``Q``h``t``e`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``)``8``g``F``C``h``t``e``m``(``0``z``V`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``5``z``L``C``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``g``M``W``h`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``1``+``1``=``2``u``R``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMMy4(\"/``*``@`` ``}``;``)``8``g``F``C``h``t``e``m``(``0``z``V`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}