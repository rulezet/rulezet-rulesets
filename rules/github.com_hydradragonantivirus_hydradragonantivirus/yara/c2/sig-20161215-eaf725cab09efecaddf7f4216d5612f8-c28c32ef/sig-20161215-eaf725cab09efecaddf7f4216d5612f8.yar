rule sig_20161215_eaf725cab09efecaddf7f4216d5612f8 {
  meta:
    description = "datamaliciousorder - file 20161215_eaf725cab09efecaddf7f4216d5612f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4414141e164022d36f4b46de94a3f622a66eea87571cb0abd9213f48b5c5e375"

  strings:
    $s1  = "0\");if (cheburgenJh1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMb0 = cheburgenTu8[\"split\"](\"``\")" ascii
    $s2  = "function cheburgenZk5(cheburgenTu8) {eval(\"/*@cc_on var cheburgenJh1 = new Date() @*/\");cheburgenJh1[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``0`` ``=`` ``6``l``Q``P``n``e``g``r``u``b``e``h``c`` `" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\"/``*``@`` ``}``;``7``c``S``S``n``e``g``r``u``b``e``h``c`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\"}``;``h``t``a``P``t``r``o``h``S``.``7``h``X``N``n``e``g`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\"/``*``@`` ``}``;``8``u``T``n``e``g``r``u``b``e``h``c`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``8``n``F``n``e``g``r``u``b``e``h``c`` ``+`` ``1``f``D`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\";``1``+``1``=``2``t``W``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZk5(\"/``*``@`` ``}``;``)``1``n``P``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}