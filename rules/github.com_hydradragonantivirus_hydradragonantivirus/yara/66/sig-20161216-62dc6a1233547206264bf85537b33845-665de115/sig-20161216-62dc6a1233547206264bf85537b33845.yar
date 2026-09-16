rule sig_20161216_62dc6a1233547206264bf85537b33845 {
  meta:
    description = "datamaliciousorder - file 20161216_62dc6a1233547206264bf85537b33845.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e2f1662bc5716440cc70e8632e16cb54211a0c6e39cef374f104ae0130b4286"

  strings:
    $s1  = "function cheburgenQp9(cheburgenIt1) {eval(\"/*@cc_on var cheburgenOBb2 = new Date() @*/\");cheburgenOBb2[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``o``P``n`" ascii
    $s3  = "n cheburgenUFq7[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"\")), 1);///////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``7``q``F``U``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``\\x22``c``k``6``h``5``x``v``j``2``r``/``m``o``c``." ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``1``+``1``=``6``p``V``W``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``o``A``Z``n`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``\\x22``c``g``r``n``t``c``4``q``q``/``m``o``c``.``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``0``u``Q``W``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``)``4``l``S``A``n``e``g``r``u``b``e``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\"/``*``@`` ``}``;``0``u``Q``W``n``e``g``r``u``b``e``h``c`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``0`` ``=`` ``5``p``W``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenQp9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}