rule sig_20161216_51227cf018ce1de3af57847a5434001d {
  meta:
    description = "datamaliciousorder - file 20161216_51227cf018ce1de3af57847a5434001d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c5221c03b8c657d1bd8b1bea1edd444c5ed0ce87cfc8bd0e249ea344de4d9de"

  strings:
    $s1  = "function cheburgenNRv0(cheburgenSRr6) {eval(\"/*@cc_on var cheburgenPYm4 = new Date() @*/\");cheburgenPYm4[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"}``;``h``t``a``P``t``r``o``h``S``.``6``a``D``P``n``e``g" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``1``+``1``=``1``w``X``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``6``d``I``n``e``g``r``u``b``e``h``c`` ``+`` ``9``m``L" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``s``K``P" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``)``1``b``R``X``n``e``g``r``u``b``e``h" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``6``r``R``S``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``4``c``O``H``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``7``c``H``G``n``e``g``r``u``b``e``h``c" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\";``1``+``1``=``1``w``X``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNRv0(\"/``*``@`` ``}``;``7``c``H``G``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}