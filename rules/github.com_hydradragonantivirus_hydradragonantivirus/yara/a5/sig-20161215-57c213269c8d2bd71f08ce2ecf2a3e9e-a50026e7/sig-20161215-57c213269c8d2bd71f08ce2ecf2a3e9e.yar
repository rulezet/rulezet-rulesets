rule sig_20161215_57c213269c8d2bd71f08ce2ecf2a3e9e {
  meta:
    description = "datamaliciousorder - file 20161215_57c213269c8d2bd71f08ce2ecf2a3e9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6988cbfa5b753df181667837adc899ce2ad1e27185ad62fac6a8621ac720de25"

  strings:
    $s1  = "function cheburgenAGm6(cheburgenLCt5) {eval(\"/*@cc_on var cheburgenOZz0 = new Date() @*/\");cheburgenOZz0[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``)``0``j``C``n``e``g``r``u``b``e``h``c" ascii
    $s5  = "turn cheburgenJZi6[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``x``I``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``x``I``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"}``;``h``t``a``P``t``r``o``h``S``.``8``j``A``n``e``g``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``u``W``O``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``0`` ``=`` ``1``t``S``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``\\x22``6``g``c``g``6``/``e``d``.``c``i``s``u``m``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``5``t``C``L``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``\\x22``\\x22`` ``+`` ``4``s``H``N``n``e``g``r``u`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\";``1``+``1``=``5``x``F``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``)``0``j``C``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenAGm6(\"/``*``@`` ``}``;``9``r``E``W``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}