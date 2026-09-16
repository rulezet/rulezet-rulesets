rule sig_20161216_3179dff28252a87674ca4124d2de9d4b {
  meta:
    description = "datamaliciousorder - file 20161216_3179dff28252a87674ca4124d2de9d4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e1d74c88d44cc51cdd0d0d6205c71ac0a20dceb83d1444e028271d200f278da"

  strings:
    $s1  = "function methSe7(methCFy3) {eval(\"/*@cc_on var methFk7 = new Date() @*/\");methFk7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``1``h``Q``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``6``b``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``6``r``N``T``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``f``H``P``h``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``3``y``F``C``h``t``e``m`` ``n``r``u``t``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"/``*``@`` ``}``;``6``b``T``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``\\x22``v``j``g``l``2``z``/``m``o``c``.``t``i``s``n`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``4``d``N``M``h``t``e``m`` ``+`` ``7``k``Q``h``t``e``m``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\"}``;``h``t``a``P``t``r``o``h``S``.``7``t``O``h``t``e``m``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methSe7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}