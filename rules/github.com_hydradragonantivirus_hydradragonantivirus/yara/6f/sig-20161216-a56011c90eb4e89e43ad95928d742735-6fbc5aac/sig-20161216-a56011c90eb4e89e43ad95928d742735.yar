rule sig_20161216_a56011c90eb4e89e43ad95928d742735 {
  meta:
    description = "datamaliciousorder - file 20161216_a56011c90eb4e89e43ad95928d742735.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb45d541fd0b76fcca3cdbf4fa5d444e8345a30dd7d77d4847a94fe1ca6febe8"

  strings:
    $s1  = "function cheburgenYQa9(cheburgenUMb9) {eval(\"/*@cc_on var cheburgenFNm3 = new Date() @*/\");cheburgenFNm3[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``1``+``1``=``8``q``R``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``0`` ``=`` ``9``e``B``Y``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"/``*``@`` ``}``;``9``z``X``n``e``g``r``u``b``e``h``c`` " ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"/``*``@`` ``}``;``)``6``e``E``V``n``e``g``r``u``b``e``h" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"}``;``h``t``a``P``t``r``o``h``S``.``6``y``B``n``e``g``r" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``3``s``N``n``e``g``r``u``b``e``h``c`` ``+`` ``3``d``Q" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``\\x22`` ``+`` ``3``f``X``n``e``g``r``u``b`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``\\x22`` ``+`` ``3``f``X``n``e``g``r``u``b`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"/``*``@`` ``}``;``9``b``M``U``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\"/``*``@`` ``}``;``9``b``M``U``n``e``g``r``u``b``e``h``c" ascii
    $s19 = "urn cheburgenXz9[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenYQa9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}