rule sig_20161216_15ed6266725b1c63d0d10878d71825db {
  meta:
    description = "datamaliciousorder - file 20161216_15ed6266725b1c63d0d10878d71825db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da63848912a3fb10fd4109393d4a75a0423af8b11fd734c84f59925dbf30e3d2"

  strings:
    $s1  = "function methNKg2(methNNh4) {eval(\"/*@cc_on var methUy0 = new Date() @*/\");methUy0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``1``+``1``=``6``l``X``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"}``;``h``t``a``P``t``r``o``h``S``.``0``w``J``h``t``e``m`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"/``*``@`` ``}``;``4``u``I``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"}``;``h``t``a``P``t``r``o``h``S``.``0``w``J``h``t``e``m`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"/``*``@`` ``}``;``4``h``N``N``h``t``e``m`` ``n``r``u``t`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"/``*``@`` ``}``;``)``1``q``N``L``h``t``e``m``(``8``f``C`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``d``C``X``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``7``w``L``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``0`` ``=`` ``4``e``C``Z``h``t``e``m`` ``r``a``v\"))), " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``0`` ``=`` ``4``e``C``Z``h``t``e``m`` ``r``a``v\"))), " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methNKg2(\";``)``\\x22``c``m``c``s``p``5``w``6``c``/``m``o``c``.``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}