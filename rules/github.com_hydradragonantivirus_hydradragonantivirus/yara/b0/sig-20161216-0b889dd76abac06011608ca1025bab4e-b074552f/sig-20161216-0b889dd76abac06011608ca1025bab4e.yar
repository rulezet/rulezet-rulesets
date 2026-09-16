rule sig_20161216_0b889dd76abac06011608ca1025bab4e {
  meta:
    description = "datamaliciousorder - file 20161216_0b889dd76abac06011608ca1025bab4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a3637f58eeb776aafa3df5b23436e4137b245e549c626d644de26597c36300a"

  strings:
    $s1  = "function methXj3(methEBw9) {eval(\"/*@cc_on var methKy5 = new Date() @*/\");methKy5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``1``+``1``=``8``c``K``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``p``B``H``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"/``*``@`` ``}``;``)``1``k``Z``M``h``t``e``m``(``9``o``L``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"/``*``@`` ``}``;``9``w``B``E``h``t``e``m`` ``n``r``u``t``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``0`` ``=`` ``5``v``G``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"/``*``@`` ``}``;``6``g``I``T``h``t``e``m`` ``n``r``u``t``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``\\x22``h``9``5``x``l``s``y``/``l``p``.``a``z``.``a`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``f``X``Y``h``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXj3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}