rule sig_20161216_c6b9573c0ab642a7c1838d95e4459009 {
  meta:
    description = "datamaliciousorder - file 20161216_c6b9573c0ab642a7c1838d95e4459009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd80aa85a4bfda4210ce26bc31df964dd3a36e501a38847641770790832d2aa"

  strings:
    $s1  = "function cheburgenPIg0(cheburgenGm6) {eval(\"/*@cc_on var cheburgenEk1 = new Date() @*/\");cheburgenEk1[\"setUTC\"+\"Seconds\"](" ascii
    $s2  = "20\");if (cheburgenEk1[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenMHy9 = cheburgenGm6[\"split\"](\"``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``9``y``H``M``n``e``g``r``u``b``e``h``c" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``6``m``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``9``y``H``M``n``e``g``r``u``b``e``h``c" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``\\x22`` ``+`` ``9``j``F``n``e``g``r``u``b`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``2``2``r``t``d``/``m``o``c``.``g``s``d``-``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s13 = "function cheburgenPIg0(cheburgenGm6) {eval(\"/*@cc_on var cheburgenEk1 = new Date() @*/\");cheburgenEk1[\"setUTC\"+\"Seconds\"](" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``1``+``1``=``5``l``X``Z``n``e``g``r``u``b``e``h``c`` " ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``1``c``g``x``t``l``m``/``m``o``c``.``k``y``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"\")), 1);//////////////////////////////////////////////" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``6``m``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``\\x22``\\x22`` ``+`` ``9``j``F``n``e``g``r``u``b`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenPIg0(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``4``l``D``B``n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}