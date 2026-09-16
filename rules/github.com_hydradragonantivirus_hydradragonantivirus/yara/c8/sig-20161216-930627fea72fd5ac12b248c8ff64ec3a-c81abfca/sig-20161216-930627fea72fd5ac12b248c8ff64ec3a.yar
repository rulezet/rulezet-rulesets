rule sig_20161216_930627fea72fd5ac12b248c8ff64ec3a {
  meta:
    description = "datamaliciousorder - file 20161216_930627fea72fd5ac12b248c8ff64ec3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98dff2a55d8262f7edb4bc6bb4730a5e89b4645df8bf902b809f52ed4fa20077"

  strings:
    $s1  = "function cheburgenYIo1(cheburgenCBi9) {eval(\"/*@cc_on var cheburgenHr7 = new Date() @*/\");cheburgenHr7[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"/``*``@`` ``}``;``6``i``F``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``n``O``n``e" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``s``Z``Z" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"}``;``h``t``a``P``t``r``o``h``S``.``8``a``W``L``n``e``g" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``0`` ``=`` ``9``x``D``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``1``+``1``=``3``u``A``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``)``\\x22``n``p``u``a``b``u``/``g``r``o``.``e``v``i``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"/``*``@`` ``}``;``9``i``B``C``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"/``*``@`` ``}``;``)``0``g``X``D``n``e``g``r``u``b``e``h" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``0`` ``=`` ``9``x``D``H``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "function cheburgenYIo1(cheburgenCBi9) {eval(\"/*@cc_on var cheburgenHr7 = new Date() @*/\");cheburgenHr7[\"setUTC\"+\"Seconds\"]" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYIo1(\";``1``+``1``=``3``u``A``A``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}