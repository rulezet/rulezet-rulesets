rule sig_20161216_e2ac99fd8eb47720a73934530e14f1cd {
  meta:
    description = "datamaliciousorder - file 20161216_e2ac99fd8eb47720a73934530e14f1cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca86ea08cc5aa2ee702625fcc38330a8b2cb06ca5f3e5617293e96c1f316505d"

  strings:
    $s1  = "function methTGg9(methWw5) {eval(\"/*@cc_on var methOq9 = new Date() @*/\");methOq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``1``+``1``=``3``n``L``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``p``V``O`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``u``B``h``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``\\x22``4``z``p``i``r``a``z``/``m``o``c``.``a``d``i" ascii
    $s9  = "function methTGg9(methWw5) {eval(\"/*@cc_on var methOq9 = new Date() @*/\");methOq9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\"}``;``h``t``a``P``t``r``o``h``S``.``9``t``Z``A``h``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``\\x22``0``0``7``k``d``u``2``2``z``z``/``g``r``o``." ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``0`` ``=`` ``6``m``B``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``0``l``W``h``t``e``m`` ``+`` ``8``v``V``h``t``e``m``=`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTGg9(\";``1``+``1``=``3``n``L``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}