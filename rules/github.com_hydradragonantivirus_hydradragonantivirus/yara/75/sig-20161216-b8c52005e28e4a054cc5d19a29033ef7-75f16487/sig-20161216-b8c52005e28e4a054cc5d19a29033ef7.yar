rule sig_20161216_b8c52005e28e4a054cc5d19a29033ef7 {
  meta:
    description = "datamaliciousorder - file 20161216_b8c52005e28e4a054cc5d19a29033ef7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bada804b942732d9b08b58e037eee110cb34b1c0829c061b13dd01d4c183ff96"

  strings:
    $s1  = "function cheburgenHHy8(cheburgenQKj7) {eval(\"/*@cc_on var cheburgenQLf4 = new Date() @*/\");cheburgenQLf4[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``7``h``S``J``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``1``+``1``=``7``d``E``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"}``;``h``t``a``P``t``r``o``h``S``.``9``q``P``n``e``g``r" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "turn cheburgenHBo2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``0`` ``=`` ``2``l``S``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``)``\\x22``h``c``d``i``g``z``z``h``/``e``m``.``i``k``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``w``N``n``e" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``1``+``1``=``7``d``E``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``7``d``O``n``e``g``r``u``b``e``h``c`` ``+`` ``0``v``X" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``2``o``B``H``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``w``N``n``e" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "function cheburgenHHy8(cheburgenQKj7) {eval(\"/*@cc_on var cheburgenQLf4 = new Date() @*/\");cheburgenQLf4[\"setUTC\"+\"Seconds" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenHHy8(\"/``*``@`` ``}``;``7``h``S``J``n``e``g``r``u``b``e``h``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}