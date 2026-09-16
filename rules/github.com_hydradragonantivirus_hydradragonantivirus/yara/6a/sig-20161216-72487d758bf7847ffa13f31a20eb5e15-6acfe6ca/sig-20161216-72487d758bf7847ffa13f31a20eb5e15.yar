rule sig_20161216_72487d758bf7847ffa13f31a20eb5e15 {
  meta:
    description = "datamaliciousorder - file 20161216_72487d758bf7847ffa13f31a20eb5e15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "777fd9d6671eaac426d00c162aaca69fe528fb1501038c19fd4392c80664ad50"

  strings:
    $s1  = "function methYZe2(methLw8) {eval(\"/*@cc_on var methBq3 = new Date() @*/\");methBq3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"/``*``@`` ``}``;``8``w``L``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"/``*``@`` ``}``;``7``a``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``\\x22``c``o``a``4``k``g``r``/``l``p``.``m``o``c``a" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``e``P``h`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``v``H``h``t``e``m`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"/``*``@`` ``}``;``7``a``F``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``7``r``M``Y``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``5``e``P``h`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``\\x22``s``w``y``v``g``u``2``n``s``/``r``a``.``m``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"/``*``@`` ``}``;``9``c``O``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``2``w``P``h``t``e``m`` ``+`` ``3``d``N``D``h``t``e``m`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``)``\\x22``h``d``f``o``1``v``f``c``s``/``m``o``c``.``a" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\"}``;``h``t``a``P``t``r``o``h``S``.``7``v``H``h``t``e``m`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methYZe2(\";``0`` ``=`` ``5``q``N``U``h``t``e``m`` ``r``a``v\"))), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}