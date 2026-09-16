rule sig_20161216_7ad47ab2177cf742b18b8dec4da5d319 {
  meta:
    description = "datamaliciousorder - file 20161216_7ad47ab2177cf742b18b8dec4da5d319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a659e9afacd67358e6f3117208f2cf6187db0c8a91a75421f5e6324ec445bb"

  strings:
    $s1  = "\"20\");if (cheburgenRa0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFh0 = cheburgenXMv0[\"split\"](\"`" ascii
    $s2  = "function cheburgenASz9(cheburgenXMv0) {eval(\"/*@cc_on var cheburgenRa0 = new Date() @*/\");cheburgenRa0[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s6  = " cheburgenFh0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"/``*``@`` ``}``;``5``j``V``S``n``e``g``r``u``b``e``h``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``0`` ``=`` ``0``p``P``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"/``*``@`` ``}``;``0``h``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``\\x22``c``w``m``o``8``r``/``a``c``.``e``c``a``r``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"/``*``@`` ``}``;``0``v``M``X``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"}``;``h``t``a``P``t``r``o``h``S``.``5``e``P``n``e``g``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"/``*``@`` ``}``;``0``h``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``w``Q``K" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``\\x22``c``g``r``n``t``c``4``q``q``/``m``o``c``.``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenASz9(\"/``*``@`` ``}``;``)``3``p``Z``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}