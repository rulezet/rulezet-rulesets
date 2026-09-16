rule sig_20161216_162a9d8e3eba8331f69c179cb877e1ea {
  meta:
    description = "datamaliciousorder - file 20161216_162a9d8e3eba8331f69c179cb877e1ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7d06e4e5a83e185147a570966d619463b7c6aa31965a1ef7ddef05e9a7b3b75"

  strings:
    $s1  = "function methXo4(methOy0) {eval(\"/*@cc_on var methLJz9 = new Date() @*/\");methLJz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methOYp5 = methOy0[\"sp\"+\"lit\"](\"``\"); return methOYp5[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``1``+``1``=``2``l``S``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\"/``*``@`` ``}``;``)``1``n``L``h``t``e``m``(``0``z``O``h``" ascii
    $s7  = "function methXo4(methOy0) {eval(\"/*@cc_on var methLJz9 = new Date() @*/\");methLJz9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\"/``*``@`` ``}``;``)``1``n``L``h``t``e``m``(``0``z``O``h``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\"/``*``@`` ``}``;``8``c``J``h``t``e``m`` ``n``r``u``t``e``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``1``+``1``=``2``l``S``h``t``e``m`` ``r``a``v``;``)``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXo4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}