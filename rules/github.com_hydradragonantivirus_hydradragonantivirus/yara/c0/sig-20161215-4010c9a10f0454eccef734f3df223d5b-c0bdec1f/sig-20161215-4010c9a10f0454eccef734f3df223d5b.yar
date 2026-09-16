rule sig_20161215_4010c9a10f0454eccef734f3df223d5b {
  meta:
    description = "datamaliciousorder - file 20161215_4010c9a10f0454eccef734f3df223d5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c7005f1a9e4de583f23612371d3ea596bd666dba3f0c605a16114712706b6a"

  strings:
    $s1  = "20\");if (cheburgenJh0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSDi3 = cheburgenJs1[\"split\"](\"``" ascii
    $s2  = "function cheburgenJZt9(cheburgenJs1) {eval(\"/*@cc_on var cheburgenJh0 = new Date() @*/\");cheburgenJh0[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"/``*``@`` ``}``;``7``j``S``A``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``0`` ``=`` ``5``v``I``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"}``;``h``t``a``P``t``r``o``h``S``.``9``z``X``n``e``g``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``1``+``1``=``0``o``O``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\"/``*``@`` ``}``;``3``i``D``S``n``e``g``r``u``b``e``h``c" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenJZt9(\";``)``\\x22``\\x22`` ``+`` ``7``g``D``A``n``e``g``r``u`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}