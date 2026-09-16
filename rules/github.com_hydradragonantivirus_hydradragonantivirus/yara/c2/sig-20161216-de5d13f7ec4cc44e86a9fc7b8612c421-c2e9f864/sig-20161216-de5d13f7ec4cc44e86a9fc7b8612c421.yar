rule sig_20161216_de5d13f7ec4cc44e86a9fc7b8612c421 {
  meta:
    description = "datamaliciousorder - file 20161216_de5d13f7ec4cc44e86a9fc7b8612c421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85bf1895b71b20e11573acdce0e4a7f3057b11b935f235480c44cd79ff8fd192"

  strings:
    $s1  = "function cheburgenQDd0(cheburgenFTf1) {eval(\"/*@cc_on var cheburgenNx8 = new Date() @*/\");cheburgenNx8[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"}``;``h``t``a``P``t``r``o``h``S``.``2``s``Z``F``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``\\x22`` ``+`` ``0``z``Z``n``e``g``r``u``b`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``i``R``n``e" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``i``R``n``e" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``p``v``r``k``l``3``9``w``0``q``/``m``o``c``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``9``g``N``H``n``e``g``r``u``b``e``h``c`` ``+`` ``0``d" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"/``*``@`` ``}``;``)``3``l``G``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``1``+``1``=``8``v``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``0`` ``=`` ``4``z``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``)``\\x22``\\x22`` ``+`` ``0``z``Z``n``e``g``r``u``b`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQDd0(\"/``*``@`` ``}``;``)``3``l``G``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}