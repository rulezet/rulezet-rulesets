rule sig_20161216_7bf8584fb528df6946efb9771676f8ed {
  meta:
    description = "datamaliciousorder - file 20161216_7bf8584fb528df6946efb9771676f8ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fbb87bac612122f240e1290a17c96a3636b3939f00bdf0235289dde6d3907d3"

  strings:
    $s1  = "function methPo3(methXVd3) {eval(\"/*@cc_on var methCz8 = new Date() @*/\");methCz8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "tUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methBe1 = methXVd3[\"sp\"+\"lit\"](\"``\"); return methBe1[\"reverse\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``)``\\x22``8``n``u``m``w``j``r``y``/``m``o``c``.``2``s`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``)``5``v``W``V``h``t``e``m``(``4``t``D``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``2``c``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``0`` ``=`` ``6``e``W``h``t``e``m`` ``r``a``v\"))), 1);/" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``)``\\x22``s``c``y``g``8``s``l``g``y``/``s``u``.``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``1``+``1``=``4``i``G``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``2``c``Y``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``)``5``v``W``V``h``t``e``m``(``4``t``D``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPo3(\"/``*``@`` ``}``;``3``d``V``X``h``t``e``m`` ``n``r``u``t``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}