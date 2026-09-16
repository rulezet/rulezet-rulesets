rule sig_20161216_c48a9ab3087add0f24d624d91f68c351 {
  meta:
    description = "datamaliciousorder - file 20161216_c48a9ab3087add0f24d624d91f68c351.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12d739001b9184233b5d79b971609a8ee98c00e7cd9773633eb7e798a00501de"

  strings:
    $s1  = "function cheburgenMj3(cheburgenBDj6) {eval(\"/*@cc_on var cheburgenCFg0 = new Date() @*/\");cheburgenCFg0[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``s``O``n``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``7``l``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``)``1``u``U``X``n``e``g``r``u``b``e``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``)``\\x22``e``0``9``k``s``i``/``p``o``t``.``e``s``i``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``2``w``G``K``n``e``g``r``u``b``e``h``c`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``6``j``D``B``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "urn cheburgenKGw2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``0`` ``=`` ``1``w``V``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"/``*``@`` ``}``;``7``l``D``n``e``g``r``u``b``e``h``c`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"\")), 1);///////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\";``)``\\x22``\\x22`` ``+`` ``7``t``D``n``e``g``r``u``b``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMj3(\"}``;``h``t``a``P``t``r``o``h``S``.``8``z``Z``n``e``g``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}