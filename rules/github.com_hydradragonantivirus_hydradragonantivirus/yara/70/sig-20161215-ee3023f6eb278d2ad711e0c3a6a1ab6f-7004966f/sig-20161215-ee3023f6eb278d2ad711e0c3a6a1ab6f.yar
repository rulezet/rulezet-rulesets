rule sig_20161215_ee3023f6eb278d2ad711e0c3a6a1ab6f {
  meta:
    description = "datamaliciousorder - file 20161215_ee3023f6eb278d2ad711e0c3a6a1ab6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac938e6cff3d04c12e41a0626e25df89bc0e18477d233ba0b853d11072fd40f8"

  strings:
    $s1  = "function cheburgenUYx5(cheburgenMZe9) {eval(\"/*@cc_on var cheburgenBw8 = new Date() @*/\");cheburgenBw8[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"/``*``@`` ``}``;``0``x``S``R``n``e``g``r``u``b``e``h``c" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``\\x22`` ``+`` ``8``b``K``n``e``g``r``u``b`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"/``*``@`` ``}``;``)``7``m``K``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``m``W``F``n``e``g" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``0`` ``=`` ``7``p``X``Q``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"\")), 1);//////////////////////////////////////////////" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``7``x``I``O``n``e``g``r``u``b``e``h``c`` ``+`` ``2``i" ascii
    $s13 = "function cheburgenUYx5(cheburgenMZe9) {eval(\"/*@cc_on var cheburgenBw8 = new Date() @*/\");cheburgenBw8[\"setUTC\"+\"Seconds\"]" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``\\x22`` ``+`` ``8``b``K``n``e``g``r``u``b`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``1``+``1``=``9``e``U``U``n``e``g``r``u``b``e``h``c`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``m``W``F``n``e``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenUYx5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}