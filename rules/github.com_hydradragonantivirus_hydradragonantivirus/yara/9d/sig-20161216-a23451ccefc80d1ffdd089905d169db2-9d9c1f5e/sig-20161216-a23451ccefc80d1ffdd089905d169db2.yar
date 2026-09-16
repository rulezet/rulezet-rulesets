rule sig_20161216_a23451ccefc80d1ffdd089905d169db2 {
  meta:
    description = "datamaliciousorder - file 20161216_a23451ccefc80d1ffdd089905d169db2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70209d82f6c0500bcff5ec4101a308e3f4cfb277c78c4430dc4c9dd065b5975"

  strings:
    $s1  = "function cheburgenHKq6(cheburgenOTg3) {eval(\"/*@cc_on var cheburgenVSu3 = new Date() @*/\");cheburgenVSu3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``3``g``T``O``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``0``e``C``O``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"}``;``h``t``a``P``t``r``o``h``S``.``2``y``X``n``e``g``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``4``y``L``R``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"}``;``h``t``a``P``t``r``o``h``S``.``2``y``X``n``e``g``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``0`` ``=`` ``0``r``Z``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``p``P``H``n" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``7``z``N``O``n``e``g``r``u``b``e``h``c`` ``+`` ``1``p" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\";``)``\\x22``\\x22`` ``+`` ``2``j``Q``X``n``e``g``r``u`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHKq6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``p``P``H``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}