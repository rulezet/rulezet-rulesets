rule sig_20161215_c256ac8aa00f8513f11fbadf8f86acce {
  meta:
    description = "datamaliciousorder - file 20161215_c256ac8aa00f8513f11fbadf8f86acce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82edba4732ec9e184ecd0a31e5ad091d6f1b45ea7d66178693a22760e840f8ab"

  strings:
    $s1  = "20\");if (cheburgenUz3[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenNPw4 = cheburgenMZx2[\"split\"](\"``" ascii
    $s2  = "function cheburgenGw6(cheburgenMZx2) {eval(\"/*@cc_on var cheburgenUz3 = new Date() @*/\");cheburgenUz3[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``)``5``l``M``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``3``h``S``n``e``g``r``u``b``e``h``c`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``9``l``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``9``r``U`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``4``w``P``N``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``9``l``Q``n``e``g``r``u``b``e``h``c`` ``+`` ``9``r``U`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``4``w``P``N``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\"/``*``@`` ``}``;``2``x``Z``M``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``\\x22``s``0``l``l``r``5``f``w``k``v``/``m``o``c``." ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``w``U``S`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenGw6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}