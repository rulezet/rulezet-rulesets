rule sig_20161216_9909d909d817580dc83bdbe383cd1b28 {
  meta:
    description = "datamaliciousorder - file 20161216_9909d909d817580dc83bdbe383cd1b28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39ce43320e12c0a51f4b706d216f9817c27dd78b8bf133c075712891c9e976fc"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methLx2 = methRm2[\"sp\"+\"lit\"](\"``\"); return methLx2[\"reverse" ascii
    $s2  = "function methAGl5(methRm2) {eval(\"/*@cc_on var methSZw8 = new Date() @*/\");methSZw8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``4``c``G``Z``h``t``e``m`` ``+`` ``0``z``Y``P``h``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\"/``*``@`` ``}``;``2``x``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "function methAGl5(methRm2) {eval(\"/*@cc_on var methSZw8 = new Date() @*/\");methSZw8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``\\x22``e``m``i``j``f``t``u``u``/``m``o``c``.``o``i" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\"/``*``@`` ``}``;``2``x``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``0``v``Y``C``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``1``+``1``=``8``a``T``S``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``8``z``N``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAGl5(\";``4``c``G``Z``h``t``e``m`` ``+`` ``0``z``Y``P``h``t``e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}