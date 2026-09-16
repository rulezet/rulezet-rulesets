rule sig_20161215_375866310e6badb18b232bc806b3f973 {
  meta:
    description = "datamaliciousorder - file 20161215_375866310e6badb18b232bc806b3f973.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a09548a318c16ef5fbd74af364e93ec101c4fb70450c05ffc09ec7bb4bf5d927"

  strings:
    $s1  = "20\");if (cheburgenYk4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenFYy8 = cheburgenAs7[\"split\"](\"``" ascii
    $s2  = "function cheburgenEIn6(cheburgenAs7) {eval(\"/*@cc_on var cheburgenYk4 = new Date() @*/\");cheburgenYk4[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``1``z``C``n``e``g``r``u``b``e``h``c`` ``+`` ``2``a``T" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\"\")), 1);//////////////////////////////////////////////" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\"}``;``h``t``a``P``t``r``o``h``S``.``3``t``Z``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\"/``*``@`` ``}``;``7``s``A``n``e``g``r``u``b``e``h``c`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``o``C``n" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\"/``*``@`` ``}``;``7``d``P``n``e``g``r``u``b``e``h``c`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``0`` ``=`` ``8``o``S``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``o``C``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``1``+``1``=``6``q``E``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\"/``*``@`` ``}``;``)``6``z``Z``O``n``e``g``r``u``b``e``h" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``g``o``7``w``u``z``e``z``a``y``/``e``s``.``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``o``7``j``c``y``/``z``t``.``o``c``.``s``r``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenEIn6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}