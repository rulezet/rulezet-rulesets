rule sig_20161215_c7d61275b0b538a65b3664a9521a1a70 {
  meta:
    description = "datamaliciousorder - file 20161215_c7d61275b0b538a65b3664a9521a1a70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b788ee58a4232522925e34f0868ac2a83954a62e6c6311188d9012e5f069919"

  strings:
    $s1  = "\"20\");if (cheburgenWWi7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenGl8 = cheburgenIe6[\"split\"](\"`" ascii
    $s2  = "function cheburgenGw0(cheburgenIe6) {eval(\"/*@cc_on var cheburgenWWi7 = new Date() @*/\");cheburgenWWi7[\"setUTC\"+\"Seconds\"]" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\"/``*``@`` ``}``;``7``a``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``0`` ``=`` ``8``q``R``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\"/``*``@`` ``}``;``7``a``U``n``e``g``r``u``b``e``h``c`` `" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``i" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``1``+``1``=``6``p``E``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``3``q``M``n``e``g``r``u``b``e``h``c`` ``+`` ``1``q``A`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``)``\\x22``\\x22`` ``+`` ``6``c``E``Y``n``e``g``r``u``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``1``+``1``=``6``p``E``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``y" ascii
    $s16 = " cheburgenGl8[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\";``0`` ``=`` ``8``q``R``N``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\"/``*``@`` ``}``;``8``l``G``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw0(\"}``;``h``t``a``P``t``r``o``h``S``.``3``f``Q``n``e``g``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}