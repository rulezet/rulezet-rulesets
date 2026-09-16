rule sig_20161216_e96ee3d005128dec0b4f5d78a469e36a {
  meta:
    description = "datamaliciousorder - file 20161216_e96ee3d005128dec0b4f5d78a469e36a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b760af5de4f3c5eb6574afb4b960a7fbb41722e743b1eab0d87c51aa3d7afda6"

  strings:
    $s1  = "function methYIa3(methHw6) {eval(\"/*@cc_on var methBm1 = new Date() @*/\");methBm1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``)``3``p``Q``h``t``e``m``(``6``f``U``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``1``t``U``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``)``3``p``Q``h``t``e``m``(``6``f``U``h`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``1``+``1``=``7``m``X``X``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``0`` ``=`` ``3``b``M``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``1``+``1``=``7``m``X``X``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``0`` ``=`` ``3``b``M``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``g``D``G``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``)``\\x22``w``s``x``y``r``f``r``a``o``w``/``m``o``c``." ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a" ascii
    $s17 = "function methYIa3(methHw6) {eval(\"/*@cc_on var methBm1 = new Date() @*/\");methBm1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``g``D``G``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\"/``*``@`` ``}``;``6``w``H``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYIa3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}