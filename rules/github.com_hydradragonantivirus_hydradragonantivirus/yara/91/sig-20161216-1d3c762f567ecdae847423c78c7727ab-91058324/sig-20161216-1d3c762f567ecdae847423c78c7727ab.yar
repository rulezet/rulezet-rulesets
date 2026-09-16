rule sig_20161216_1d3c762f567ecdae847423c78c7727ab {
  meta:
    description = "datamaliciousorder - file 20161216_1d3c762f567ecdae847423c78c7727ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02f78613a341378bf65e54afe0aacbae638cb291ca2f54b25fd1ee06801a4816"

  strings:
    $s1  = "function methWl2(methGIe3) {eval(\"/*@cc_on var methPx5 = new Date() @*/\");methPx5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``r``S``E``h``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``0`` ``=`` ``5``l``M``K``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\"/``*``@`` ``}``;``3``e``I``G``h``t``e``m`` ``n``r``u``t``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``0`` ``=`` ``5``l``M``K``h``t``e``m`` ``r``a``v\"))), 1" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``y``w``5``2``g``z``n``e``j``1``/``z``c``.``o`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``j``M``T``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\"/``*``@`` ``}``;``2``f``I``S``h``t``e``m`` ``n``r``u``t``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWl2(\"/``*``@`` ``}``;``)``0``e``S``h``t``e``m``(``8``z``N``J``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}