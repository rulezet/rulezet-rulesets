rule sig_20161216_ca5b41f5883101b05bb47df0956398fc {
  meta:
    description = "datamaliciousorder - file 20161216_ca5b41f5883101b05bb47df0956398fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef179c07668fa85d9a5ce644ce0923a783b86b76ad101e080fa3f1263328aec4"

  strings:
    $s1  = "0\");if (cheburgenCq5[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenJJx7 = cheburgenEy2[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenMq9(cheburgenEy2) {eval(\"/*@cc_on var cheburgenCq5 = new Date() @*/\");cheburgenCq5[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"/``*``@`` ``}``;``7``x``J``J``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``l``w``m``8``r``t``h``o``p``/``k``d``.``e``v" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``p``H``O`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``u" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``w" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"/``*``@`` ``}``;``)``6``e``O``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``u" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\"/``*``@`` ``}``;``7``n``G``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``w" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMq9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``p``H``O`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}