rule sig_20161216_14d95c7a7a08eb2b44f17ea79517a91b {
  meta:
    description = "datamaliciousorder - file 20161216_14d95c7a7a08eb2b44f17ea79517a91b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "658d0bd47bb324497fce55e885133335ba859cb1b444a4f2a8bdd8d06b346d7c"

  strings:
    $s1  = "function cheburgenIj6(cheburgenSZb4) {eval(\"/*@cc_on var cheburgenLh6 = new Date() @*/\");cheburgenLh6[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenLh6[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenSIc0 = cheburgenSZb4[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``y``G``n``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"/``*``@`` ``}``;``0``c``I``S``n``e``g``r``u``b``e``h``c`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``0`` ``=`` ``3``z``K``n``e``g``r``u``b``e``h``c`` ``r`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"/``*``@`` ``}``;``)``8``n``A``n``e``g``r``u``b``e``h``c`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``9``t``I``n`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``1``+``1``=``2``m``F``G``n``e``g``r``u``b``e``h``c`` `" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``1``+``1``=``2``m``F``G``n``e``g``r``u``b``e``h``c`` `" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``)``\\x22``7``u``l``k``m``/``m``o``c``.``i``h``s``o``a" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"/``*``@`` ``}``;``4``b``Z``S``n``e``g``r``u``b``e``h``c`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"\")), 1);///////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``1``m``F``G``n``e``g``r``u``b``e``h``c`` ``+`` ``8``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\";``)``\\x22``p``a``h``5``d``d``w``b``c``5``/``m``o``c``." ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenIj6(\"/``*``@`` ``}``;``4``b``Z``S``n``e``g``r``u``b``e``h``c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}