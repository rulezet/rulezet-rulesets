rule sig_20161216_5e7551c3f5edda0bce903353a0af8799 {
  meta:
    description = "datamaliciousorder - file 20161216_5e7551c3f5edda0bce903353a0af8799.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b443efc484a1170b36fb94bcc187d9de24995f3f5ecf30341d7df287917646f"

  strings:
    $s1  = "function cheburgenJm0(cheburgenZi5) {eval(\"/*@cc_on var cheburgenUHb1 = new Date() @*/\");cheburgenUHb1[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenUHb1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEb6 = cheburgenZi5[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``\\x22``\\x22`` ``+`` ``1``a``R``Y``n``e``g``r``u``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``w``O``H``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``6``b``E``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``f``F``W`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``w``O``H``n`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``f``F``W`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``i" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``o" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\"/``*``@`` ``}``;``)``3``x``E``G``n``e``g``r``u``b``e``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``l" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJm0(\";``1``+``1``=``2``x``C``L``n``e``g``r``u``b``e``h``c`` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}