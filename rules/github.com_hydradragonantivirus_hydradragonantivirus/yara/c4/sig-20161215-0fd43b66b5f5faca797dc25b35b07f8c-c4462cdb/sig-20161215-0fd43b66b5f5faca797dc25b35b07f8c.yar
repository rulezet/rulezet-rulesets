rule sig_20161215_0fd43b66b5f5faca797dc25b35b07f8c {
  meta:
    description = "datamaliciousorder - file 20161215_0fd43b66b5f5faca797dc25b35b07f8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "504ab754cfa87242dce7a666ece22dc305686838a829cc617b122b4ff8947732"

  strings:
    $s1  = "function cheburgenMRv8(cheburgenGLr4) {eval(\"/*@cc_on var cheburgenMe8 = new Date() @*/\");cheburgenMe8[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"}``;``h``t``a``P``t``r``o``h``S``.``6``z``M``S``n``e``g" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``\\x22``f``x``u``g``t``j``z``/``m``o``c``.``i``n``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"/``*``@`` ``}``;``)``8``u``C``n``e``g``r``u``b``e``h``c" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``n``O``R``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``\\x22``\\x22`` ``+`` ``5``n``X``D``n``e``g``r``u`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``9``w``T``U``n``e``g``r``u``b``e``h``c`` ``+`` ``3``p" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"/``*``@`` ``}``;``)``8``u``C``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"/``*``@`` ``}``;``9``q``G``X``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"/``*``@`` ``}``;``9``o``S``Z``n``e``g``r``u``b``e``h``c" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\"}``;``h``t``a``P``t``r``o``h``S``.``6``z``M``S``n``e``g" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenMRv8(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``s``C``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}