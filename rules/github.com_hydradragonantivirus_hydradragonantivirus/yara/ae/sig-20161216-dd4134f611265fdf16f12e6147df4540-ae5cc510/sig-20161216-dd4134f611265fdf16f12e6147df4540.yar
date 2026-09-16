rule sig_20161216_dd4134f611265fdf16f12e6147df4540 {
  meta:
    description = "datamaliciousorder - file 20161216_dd4134f611265fdf16f12e6147df4540.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3247f90fcc790a8eb39e87c4a5ecab1123d7ff4b34962ac0025757587aaa0575"

  strings:
    $s1  = "function methWNj4(methOWq7) {eval(\"/*@cc_on var methAJd9 = new Date() @*/\");methAJd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methYXw8 = methOWq7[\"sp\"+\"lit\"](\"``\"); return methYXw8[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``q``K``W``h`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\"/``*``@`` ``}``;``7``q``W``O``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\"/``*``@`` ``}``;``8``w``X``Y``h``t``e``m`` ``n``r``u``t`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``1``+``1``=``7``e``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\"/``*``@`` ``}``;``4``d``K``L``h``t``e``m`` ``n``r``u``t`" ascii
    $s14 = "function methWNj4(methOWq7) {eval(\"/*@cc_on var methAJd9 = new Date() @*/\");methAJd9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``y``c``h``j``v``f``/``m``o``c``.``y``t``r``e" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``h``3``e``i``s``m``b``6``5``g``/``m``o``c``." ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``0`` ``=`` ``5``b``Y``h``t``e``m`` ``r``a``v\"))), 1);" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methWNj4(\";``)``\\x22``w``n``v``s``s``q``s``s``9``/``d``i``.``o``c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}