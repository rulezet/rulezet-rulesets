rule sig_20161216_b846fbad603b7e27c022b5ea5e82bc70 {
  meta:
    description = "datamaliciousorder - file 20161216_b846fbad603b7e27c022b5ea5e82bc70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7c0a9cad88a0fe28727f3f9a3c56921e196174147ca5286e7338e4f27433941"

  strings:
    $s1  = "function methKUp9(methSYo1) {eval(\"/*@cc_on var methHn7 = new Date() @*/\");methHn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``f``G``h``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``i``Y``E``h``t``e`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``y``Y``P`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\"}``;``h``t``a``P``t``r``o``h``S``.``1``i``Y``E``h``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``y``Y``P`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``8``m``K``G``h``t``e``m`` ``+`` ``7``b``F``h``t``e``m`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``0`` ``=`` ``9``a``L``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``m``j``h``e``1``c``/``a``c``.``s``o``r``v``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methKUp9(\";``1``+``1``=``2``q``V``h``t``e``m`` ``r``a``v``;``)``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}