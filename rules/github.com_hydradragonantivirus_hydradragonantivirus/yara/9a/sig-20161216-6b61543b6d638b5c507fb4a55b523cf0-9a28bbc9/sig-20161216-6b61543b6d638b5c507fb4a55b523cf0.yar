rule sig_20161216_6b61543b6d638b5c507fb4a55b523cf0 {
  meta:
    description = "datamaliciousorder - file 20161216_6b61543b6d638b5c507fb4a55b523cf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbd4bf4ba5f8178cdc68e4caccf1aba75338212b3063231a22fb660ef85a00dc"

  strings:
    $s1  = "function methJTp2(methDIm6) {eval(\"/*@cc_on var methEy7 = new Date() @*/\");methEy7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``t``x``d``f``4``b``l``j``/``m``o``c``.``r``a" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``0`` ``=`` ``1``p``R``M``h``t``e``m`` ``r``a``v\"))), " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\"}``;``h``t``a``P``t``r``o``h``S``.``3``m``R``h``t``e``m`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``1``+``1``=``3``d``K``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``i``M``T``h`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``0`` ``=`` ``1``p``R``M``h``t``e``m`` ``r``a``v\"))), " ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``o``B``D`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``1``+``1``=``3``d``K``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``l``o``u``t``a``i``x``j``/``m``o``c``.``e``m" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\"/``*``@`` ``}``;``1``t``C``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methJTp2(\"/``*``@`` ``}``;``6``m``I``D``h``t``e``m`` ``n``r``u``t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}