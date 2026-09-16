rule sig_20161216_ae06687957b03b9e0f8e9b6a8f728cd1 {
  meta:
    description = "datamaliciousorder - file 20161216_ae06687957b03b9e0f8e9b6a8f728cd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c87efc8c19debc197375e43a062580b53d3d0cec6e82be5127849571339ecd"

  strings:
    $s1  = "function methFLc4(methZPc5) {eval(\"/*@cc_on var methCi2 = new Date() @*/\");methCi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``g``m``k``6``n``c``o``k``e``w``/``m``o``c``." ascii
    $s3  = "function methFLc4(methZPc5) {eval(\"/*@cc_on var methCi2 = new Date() @*/\");methCi2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``)``2``i``J``h``t``e``m``(``3``o``F``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``5``s``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``)``2``i``J``h``t``e``m``(``3``o``F``h`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``s``d``m``v``k``w``/``g``r``o``.``t``c``i``r" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``5``s``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``3``h``T``O``h``t``e``m`` ``+`` ``6``m``S``K``h``t``e`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``e``G``h``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methFLc4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}