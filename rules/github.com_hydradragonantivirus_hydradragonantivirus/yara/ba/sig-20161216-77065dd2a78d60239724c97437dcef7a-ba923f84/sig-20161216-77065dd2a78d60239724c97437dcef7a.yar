rule sig_20161216_77065dd2a78d60239724c97437dcef7a {
  meta:
    description = "datamaliciousorder - file 20161216_77065dd2a78d60239724c97437dcef7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31693d6ac79abf21a61d8521f4a63fc5f2a77c23b2123ea2b2652220a856eb61"

  strings:
    $s1  = "function cheburgenVv0(cheburgenYIk9) {eval(\"/*@cc_on var cheburgenRBz9 = new Date() @*/\");cheburgenRBz9[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``y``Y``Z`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``y``N``n``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``0`` ``=`` ``7``m``S``Q``n``e``g``r``u``b``e``h``c`` `" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"/``*``@`` ``}``;``0``p``I``E``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s9  = "function cheburgenVv0(cheburgenYIk9) {eval(\"/*@cc_on var cheburgenRBz9 = new Date() @*/\");cheburgenRBz9[\"setUTC\"+\"Seconds\"" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``1``+``1``=``8``v``P``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s12 = "urn cheburgenEIp0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"/``*``@`` ``}``;``7``u``H``n``e``g``r``u``b``e``h``c`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"/``*``@`` ``}``;``)``2``k``W``R``n``e``g``r``u``b``e``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``\\x22``b``8``d``d``d``q``p``n``/``e``c``a``s``l``a" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``y``Y``Z`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"}``;``h``t``a``P``t``r``o``h``S``.``7``p``L``n``e``g``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVv0(\"/``*``@`` ``}``;``0``p``I``E``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}