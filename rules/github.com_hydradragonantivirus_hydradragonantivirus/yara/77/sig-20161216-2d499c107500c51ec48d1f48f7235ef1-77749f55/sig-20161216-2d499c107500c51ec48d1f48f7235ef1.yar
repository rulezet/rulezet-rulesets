rule sig_20161216_2d499c107500c51ec48d1f48f7235ef1 {
  meta:
    description = "datamaliciousorder - file 20161216_2d499c107500c51ec48d1f48f7235ef1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52e0f09012ca4b33e5cbd9adb9216aa21c083388c7255ba6b14f8eb84ce265fa"

  strings:
    $s1  = "0\");if (cheburgenEi9[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSMz7 = cheburgenXl5[\"split\"](\"``\"" ascii
    $s2  = "function cheburgenNd6(cheburgenXl5) {eval(\"/*@cc_on var cheburgenEi9 = new Date() @*/\");cheburgenEi9[\"setUTC\"+\"Seconds\"](" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``g``U``n`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"/``*``@`` ``}``;``2``y``E``K``n``e``g``r``u``b``e``h``c`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"/``*``@`` ``}``;``7``z``M``S``n``e``g``r``u``b``e``h``c`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``5``o``B``L``n``e``g``r``u``b``e``h``c`` ``+`` ``0``d`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``\\x22``b``l``m``6``d``b``u``y``z``/``u``r``.``a``r" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``0`` ``=`` ``7``i``Y``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"/``*``@`` ``}``;``5``l``X``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``g``U``n`" ascii
    $s16 = "function cheburgenNd6(cheburgenXl5) {eval(\"/*@cc_on var cheburgenEi9 = new Date() @*/\");cheburgenEi9[\"setUTC\"+\"Seconds\"](" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\";``)``\\x22``p``2``y``8``3``l``1``/``m``o``c``.``t``n``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"}``;``h``t``a``P``t``r``o``h``S``.``8``y``C``n``e``g``r`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNd6(\"/``*``@`` ``}``;``)``0``g``P``R``n``e``g``r``u``b``e``h`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}