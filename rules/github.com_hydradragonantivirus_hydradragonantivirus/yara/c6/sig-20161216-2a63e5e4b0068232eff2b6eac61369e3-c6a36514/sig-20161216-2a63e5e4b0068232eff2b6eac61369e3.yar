rule sig_20161216_2a63e5e4b0068232eff2b6eac61369e3 {
  meta:
    description = "datamaliciousorder - file 20161216_2a63e5e4b0068232eff2b6eac61369e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0128641db9aa937441d4346c9e6f260cad0067224e05e2f576a30d7bb2546c50"

  strings:
    $s1  = "function cheburgenBl4(cheburgenHAe6) {eval(\"/*@cc_on var cheburgenCm0 = new Date() @*/\");cheburgenCm0[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenCm0[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenOa3 = cheburgenHAe6[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"}``;``h``t``a``P``t``r``o``h``S``.``9``q``M``n``e``g``r`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``0``g``v``9``4``c``2``d``y``/``m``o``c``.``k" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"/``*``@`` ``}``;``)``7``f``I``J``n``e``g``r``u``b``e``h`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``x``s``m``3``o``9``h``/``m``o``c``.``m``i``s" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``x``G``n``e`" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``i``g``y``l``l``2``e``x``/``m``o``c``.``s``d" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``)``\\x22``\\x22`` ``+`` ``4``w``P``Y``n``e``g``r``u``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"/``*``@`` ``}``;``6``e``A``H``n``e``g``r``u``b``e``h``c`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``1``+``1``=``9``m``S``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenBl4(\"/``*``@`` ``}``;``6``e``A``H``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}