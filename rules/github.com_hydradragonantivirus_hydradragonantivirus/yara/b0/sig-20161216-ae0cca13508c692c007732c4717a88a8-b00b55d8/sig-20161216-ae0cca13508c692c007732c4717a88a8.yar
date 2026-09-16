rule sig_20161216_ae0cca13508c692c007732c4717a88a8 {
  meta:
    description = "datamaliciousorder - file 20161216_ae0cca13508c692c007732c4717a88a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb44b76b01730abce0402b54528c883c73cc091e68e95f9b408dfa99c13e76a1"

  strings:
    $s1  = "function cheburgenOJs4(cheburgenBFe7) {eval(\"/*@cc_on var cheburgenRy0 = new Date() @*/\");cheburgenRy0[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"}``;``h``t``a``P``t``r``o``h``S``.``0``k``F``n``e``g``r" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``8``z``M``n``e``g``r``u``b``e``h``c`` ``+`` ``2``w``K" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``1``+``1``=``8``z``P``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"\")), 1);//////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``q``Z``n``e" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``1``+``1``=``8``z``P``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "function cheburgenOJs4(cheburgenBFe7) {eval(\"/*@cc_on var cheburgenRy0 = new Date() @*/\");cheburgenRy0[\"setUTC\"+\"Seconds\"]" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"/``*``@`` ``}``;``1``d``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``n``Y``R" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"/``*``@`` ``}``;``1``d``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``)``\\x22``a``p``t``7``u``9``p``v``/``m``o``c``.``t``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenOJs4(\";``0`` ``=`` ``5``h``B``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}