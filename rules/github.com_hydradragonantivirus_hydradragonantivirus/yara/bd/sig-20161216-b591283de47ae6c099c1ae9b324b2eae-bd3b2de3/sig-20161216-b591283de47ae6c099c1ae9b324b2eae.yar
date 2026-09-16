rule sig_20161216_b591283de47ae6c099c1ae9b324b2eae {
  meta:
    description = "datamaliciousorder - file 20161216_b591283de47ae6c099c1ae9b324b2eae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b2582a4533afa88a005e21a692f7d6d63ece8cb223172bdd07c6b391b44247"

  strings:
    $s1  = "function methXNc7(methKh7) {eval(\"/*@cc_on var methRLo8 = new Date() @*/\");methRLo8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s2  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methGDa7 = methKh7[\"sp\"+\"lit\"](\"``\"); return methGDa7[\"revers" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``)``2``u``P``h``t``e``m``(``9``m``P``h`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``7``a``D``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``6``k``U``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``7``a``D``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``1``+``1``=``6``w``G``O``h``t``e``m`` ``r``a``v``;``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``j``4``n``e``y``l``7``s``/``h``c``.``f``a``e" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``d``Y``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``w``t``n``g``c``r``s``u``/``m``o``c``.``o``n" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``)``2``u``P``h``t``e``m``(``9``m``P``h`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``n``A``L``h`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``6``n``A``L``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``d``Y``h`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methXNc7(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}