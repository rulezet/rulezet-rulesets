rule sig_20161216_639ff6046a63d57b27eef33f2d8f0233 {
  meta:
    description = "datamaliciousorder - file 20161216_639ff6046a63d57b27eef33f2d8f0233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f00aa57c8e2da2db1d72d48957940d063a649c0f9b613a48ba7a689bda9148d"

  strings:
    $s1  = "function methTMk3(methFu7) {eval(\"/*@cc_on var methPRj8 = new Date() @*/\");methPRj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methZm2 = methFu7[\"sp\"+\"lit\"](\"``\"); return methZm2[\"reverse" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``f``H``h``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``1``+``1``=``6``v``I``I``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``\\x22``e``s``l``z``2``i``o``w``4``/``a``c``.``s``o" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``2``m``Z``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``0``y``D``h`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``2``w``D``P``h``t``e``m`` ``n``r``u``t`" ascii
    $s10 = "function methTMk3(methFu7) {eval(\"/*@cc_on var methPRj8 = new Date() @*/\");methPRj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``2``w``D``P``h``t``e``m`` ``n``r``u``t`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``9``f``H``h``t`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"/``*``@`` ``}``;``)``9``g``I``U``h``t``e``m``(``0``a``T`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``1``+``1``=``6``v``I``I``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methTMk3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}