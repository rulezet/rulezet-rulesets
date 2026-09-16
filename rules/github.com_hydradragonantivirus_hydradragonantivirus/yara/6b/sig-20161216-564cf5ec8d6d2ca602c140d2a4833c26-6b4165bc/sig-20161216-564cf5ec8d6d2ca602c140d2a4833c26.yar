rule sig_20161216_564cf5ec8d6d2ca602c140d2a4833c26 {
  meta:
    description = "datamaliciousorder - file 20161216_564cf5ec8d6d2ca602c140d2a4833c26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9063eccfcd807812d0c5894a8b8f8e222ca638fa39ceef98cb519f13b7fe98a4"

  strings:
    $s1  = "function methSPc9(methSg5) {eval(\"/*@cc_on var methNt9 = new Date() @*/\");methNt9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"/``*``@`` ``}``;``2``n``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``g``N``h``t`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``0`` ``=`` ``7``u``G``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii
    $s14 = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methFn2 = methSg5[\"sp\"+\"lit\"](\"``\"); return methFn2[\"reverse\"]()" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``g``N``h``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSPc9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}