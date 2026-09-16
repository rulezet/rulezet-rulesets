rule sig_20161216_45ce9aca4d8f547f186cf3a3c8d8be0f {
  meta:
    description = "datamaliciousorder - file 20161216_45ce9aca4d8f547f186cf3a3c8d8be0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e37d7d9acc61c314ac8a3921e7a2fad5bf28f17348e10467978f45e3e8a72fcf"

  strings:
    $s1  = "function methMUh6(methJCy8) {eval(\"/*@cc_on var methUDs4 = new Date() @*/\");methUDs4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methGs8 = methJCy8[\"sp\"+\"lit\"](\"``\"); return methGs8[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"/``*``@`` ``}``;``3``e``O``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``r``J``W`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"/``*``@`` ``}``;``)``9``i``N``I``h``t``e``m``(``9``h``Q`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"/``*``@`` ``}``;``)``9``i``N``I``h``t``e``m``(``9``h``Q`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"/``*``@`` ``}``;``8``y``C``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"}``;``h``t``a``P``t``r``o``h``S``.``7``s``B``V``h``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``1``l``M``h``t``e``m`` ``+`` ``0``p``Q``h``t``e``m``=`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``1``+``1``=``7``z``V``C``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``\\x22``v``0``s``t``3``/``m``o``c``.``g``u``e``r``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\"/``*``@`` ``}``;``8``y``C``J``h``t``e``m`` ``n``r``u``t`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methMUh6(\";``)``\\x22``f``i``c``4``7``b``x``3``d``2``/``r``f``.``e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}