rule sig_20161216_21ec6ec855476df62d251859c2dac383 {
  meta:
    description = "datamaliciousorder - file 20161216_21ec6ec855476df62d251859c2dac383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd3b29f30dce0092ac48de94c2df5fc5f9dc136b8260fb4df1ceb1a0f49dc238"

  strings:
    $s1  = "function methNBx5(methDm3) {eval(\"/*@cc_on var methRv3 = new Date() @*/\");methRv3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``0`` ``=`` ``4``l``U``C``h``t``e``m`` ``r``a``v\"))), " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``3``m``D``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``7``a``T``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``f``E``Q``h`" ascii
    $s11 = "function methNBx5(methDm3) {eval(\"/*@cc_on var methRv3 = new Date() @*/\");methRv3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``)``2``t``O``h``t``e``m``(``3``y``Y``M`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``f``E``Q``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``3``m``D``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``4``j``J``h`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``4``d``X``h``t``e``m`` ``+`` ``5``r``N``W``h``t``e``m`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\"/``*``@`` ``}``;``)``2``t``O``h``t``e``m``(``3``y``Y``M`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNBx5(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}