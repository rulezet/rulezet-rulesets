rule sig_20161216_dd33b551bdb83671a4e1d888d461805f {
  meta:
    description = "datamaliciousorder - file 20161216_dd33b551bdb83671a4e1d888d461805f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6bf5ea0aab94463b43e1217cf35a351aafa7105626061dd2ef6f7729b958fe1"

  strings:
    $s1  = "function cheburgenVIz5(cheburgenDp6) {eval(\"/*@cc_on var cheburgenGb7 = new Date() @*/\");cheburgenGb7[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenGb7[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenJQw0 = cheburgenDp6[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "cheburgenJQw0[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``g``A``n" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"/``*``@`` ``}``;``)``4``y``G``n``e``g``r``u``b``e``h``c" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"/``*``@`` ``}``;``)``4``y``G``n``e``g``r``u``b``e``h``c" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``2``e``C``I``n``e``g``r``u``b``e``h``c`` ``+`` ``5``d" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``0`` ``=`` ``9``j``L``V``n``e``g``r``u``b``e``h``c`` " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``i``H``n``e" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"\")), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\";``1``+``1``=``5``i``V``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"/``*``@`` ``}``;``0``w``Q``J``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenVIz5(\"/``*``@`` ``}``;``2``m``Q``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}