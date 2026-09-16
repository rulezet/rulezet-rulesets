rule sig_20161216_861cc1d55f3d97869041acef16f2f610 {
  meta:
    description = "datamaliciousorder - file 20161216_861cc1d55f3d97869041acef16f2f610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8e0ce3215acb89aa8814525e8ab20596fb13685deef6e0d0d60fc4e05f38380"

  strings:
    $s1  = "function methEt8(methHx2) {eval(\"/*@cc_on var methIk5 = new Date() @*/\");methIk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s2  = "function methEt8(methHx2) {eval(\"/*@cc_on var methIk5 = new Date() @*/\");methIk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (me" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``6``d``M``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``)``4``n``M``h``t``e``m``(``8``d``E``F``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``2``x``H``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``0``h``W``h``t``e``m`` ``+`` ``8``b``L``N``h``t``e``m``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``)``4``n``M``h``t``e``m``(``8``d``E``F``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``1``l``V``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``0`` ``=`` ``5``r``P``U``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methEt8(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}