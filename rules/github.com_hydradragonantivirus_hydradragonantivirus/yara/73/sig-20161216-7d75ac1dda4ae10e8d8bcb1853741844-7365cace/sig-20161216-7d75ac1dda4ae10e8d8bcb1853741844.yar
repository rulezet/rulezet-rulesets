rule sig_20161216_7d75ac1dda4ae10e8d8bcb1853741844 {
  meta:
    description = "datamaliciousorder - file 20161216_7d75ac1dda4ae10e8d8bcb1853741844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6b4679a376037e5dd0e849f81658d2a41fc596191247ab04609c6e6eda47acd"

  strings:
    $s1  = "function methIDr1(methQXn5) {eval(\"/*@cc_on var methEy9 = new Date() @*/\");methEy9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``)``6``l``Q``h``t``e``m``(``7``z``J``R`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``y``K``E`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``8``b``A``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``)``6``l``Q``h``t``e``m``(``7``z``J``R`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``m``P``h``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``8``z``R``h``t``e``m`` ``+`` ``4``t``F``h``t``e``m``=`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"}``;``h``t``a``P``t``r``o``h``S``.``1``z``A``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``\\x22``x``r``m``h``w``i``j``q``/``m``o``c``.``y``l" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``\\x22``e``m``x``l``8``l``a``q``/``e``b``.``s``t``n" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``)``\\x22``n``u``5``d``f``a``r``/``m``o``c``.``n``v``v" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``8``z``R``h``t``e``m`` ``+`` ``4``t``F``h``t``e``m``=`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\"/``*``@`` ``}``;``8``b``A``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methIDr1(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}