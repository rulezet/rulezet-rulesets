rule sig_20161215_6207c3bc52b5e3c4c631cdff270f729d {
  meta:
    description = "datamaliciousorder - file 20161215_6207c3bc52b5e3c4c631cdff270f729d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bbfb378a5b7122ac62707bb4ed578d6c674bce16adf46256c69b81a1e218613"

  strings:
    $s1  = "function cheburgenRXt9(cheburgenLCv7) {eval(\"/*@cc_on var cheburgenDQv1 = new Date() @*/\");cheburgenDQv1[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``9``t``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``0``c``T" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``s``W``E``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``s``W``E``n" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``8``k``G``G``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``0`` ``=`` ``2``x``J``J``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"/``*``@`` ``}``;``7``v``C``L``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``)``\\x22``\\x22`` ``+`` ``5``d``F``U``n``e``g``r``u`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``1``+``1``=``9``f``Y``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "function cheburgenRXt9(cheburgenLCv7) {eval(\"/*@cc_on var cheburgenDQv1 = new Date() @*/\");cheburgenDQv1[\"setUTC\"+\"Seconds" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\";``1``+``1``=``9``f``Y``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRXt9(\"}``;``h``t``a``P``t``r``o``h``S``.``8``t``V``n``e``g``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}