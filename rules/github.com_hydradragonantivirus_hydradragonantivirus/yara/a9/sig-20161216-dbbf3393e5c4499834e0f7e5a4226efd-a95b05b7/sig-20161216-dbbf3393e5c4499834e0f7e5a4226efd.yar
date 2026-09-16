rule sig_20161216_dbbf3393e5c4499834e0f7e5a4226efd {
  meta:
    description = "datamaliciousorder - file 20161216_dbbf3393e5c4499834e0f7e5a4226efd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb830fb5ace452634c7088f3ee798b658ca9811d39e4756a38e74ec681a1ec4"

  strings:
    $s1  = "20\");if (cheburgenBo1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenKWh4 = cheburgenMLi0[\"split\"](\"``" ascii
    $s2  = "function cheburgenDq5(cheburgenMLi0) {eval(\"/*@cc_on var cheburgenBo1 = new Date() @*/\");cheburgenBo1[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"/``*``@`` ``}``;``7``l``X``A``n``e``g``r``u``b``e``h``c`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``\\x22``a``i``j``1``p``7``/``u``r``.``h``c``e``t``-" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``d``T``R`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``0`` ``=`` ``5``g``M``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"}``;``h``t``a``P``t``r``o``h``S``.``2``n``L``n``e``g``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``6``y``B``J``n``e``g``r``u``b``e``h``c`` ``+`` ``0``z`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"/``*``@`` ``}``;``4``h``W``K``n``e``g``r``u``b``e``h``c`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"/``*``@`` ``}``;``0``i``L``M``n``e``g``r``u``b``e``h``c`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``k``H``n``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``\\x22``\\x22`` ``+`` ``4``g``M``n``e``g``r``u``b``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDq5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}