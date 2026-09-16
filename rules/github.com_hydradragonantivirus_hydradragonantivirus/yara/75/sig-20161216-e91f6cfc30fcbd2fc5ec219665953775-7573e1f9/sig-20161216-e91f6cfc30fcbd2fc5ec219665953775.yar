rule sig_20161216_e91f6cfc30fcbd2fc5ec219665953775 {
  meta:
    description = "datamaliciousorder - file 20161216_e91f6cfc30fcbd2fc5ec219665953775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2ca14d91af4ef00f12f79c28a34c5d04c12a44147507e253f9a336d4721b97f"

  strings:
    $s1  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZYd8 = methZh3[\"sp\"+\"lit\"](\"``\"); return methZYd8[\"reverse" ascii
    $s2  = "function methCk3(methZh3) {eval(\"/*@cc_on var methEGt1 = new Date() @*/\");methEGt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"/``*``@`` ``}``;``)``0``m``N``X``h``t``e``m``(``7``s``X``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``h``U``h``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``8``t``9``2``p``/``a``c``.``c``o``w``y``m``.`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``u``T``h``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"/``*``@`` ``}``;``9``o``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"/``*``@`` ``}``;``8``d``Y``Z``h``t``e``m`` ``n``r``u``t``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"}``;``h``t``a``P``t``r``o``h``S``.``0``m``U``S``h``t``e``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``0`` ``=`` ``7``g``I``D``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``2``j``A``h``t``e``m`` ``+`` ``7``s``Y``h``t``e``m``=``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``u``T``h``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``1``+``1``=``3``v``V``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\";``)``\\x22``c``d``u``p``o``/``m``o``c``.``p``r``o``c``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methCk3(\"\"))), 1);///////////////////////////////////////////////" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}