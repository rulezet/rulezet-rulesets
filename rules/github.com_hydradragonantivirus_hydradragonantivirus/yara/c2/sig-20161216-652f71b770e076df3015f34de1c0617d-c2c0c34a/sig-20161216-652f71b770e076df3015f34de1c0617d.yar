rule sig_20161216_652f71b770e076df3015f34de1c0617d {
  meta:
    description = "datamaliciousorder - file 20161216_652f71b770e076df3015f34de1c0617d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e3624ec1f31fff68d4f95923ccb8b9e020694951174334597cad2f49762b1d0"

  strings:
    $s1  = "function cheburgenMYa0(cheburgenBBt1) {eval(\"/*@cc_on var cheburgenWMu1 = new Date() @*/\");cheburgenWMu1[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``\\x22``\\x22`` ``+`` ``9``k``V``T``n``e``g``r``u`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``9``y``Q``N``n``e``g``r``u``b``e``h``c`` ``+`` ``9``v" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"}``;``h``t``a``P``t``r``o``h``S``.``9``f``G``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``1``+``1``=``4``y``C``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``i``C``n" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"}``;``h``t``a``P``t``r``o``h``S``.``9``f``G``n``e``g``r" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``\\x22``g``9``t``o``f``a``p``n``p``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``\\x22``\\x22`` ``+`` ``9``k``V``T``n``e``g``r``u`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``9``y``Q``N``n``e``g``r``u``b``e``h``c`` ``+`` ``9``v" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"/``*``@`` ``}``;``3``l``H``Y``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"/``*``@`` ``}``;``)``2``q``V``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"/``*``@`` ``}``;``)``2``q``V``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\"/``*``@`` ``}``;``1``t``B``B``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMYa0(\";``0`` ``=`` ``4``b``Z``X``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}