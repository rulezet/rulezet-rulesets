rule sig_20161215_34e6d18f1c01066c97ba5980eb6646bf {
  meta:
    description = "datamaliciousorder - file 20161215_34e6d18f1c01066c97ba5980eb6646bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38b030fb72c333258df108390e68a999dcda0d7edb6b610cb514268d01e118de"

  strings:
    $s1  = "function cheburgenRKr9(cheburgenOk2) {eval(\"/*@cc_on var cheburgenHCd4 = new Date() @*/\");cheburgenHCd4[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``0`` ``=`` ``0``s``S``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``i``7``l``h``0``n``h``/``m``o``c``.``z``i``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\"/``*``@`` ``}``;``2``k``O``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "rn cheburgenSFr2[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``e``w``o``b``h``/``m``o``c``.``8``6``o``h``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``0`` ``=`` ``0``s``S``T``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``\\x22`` ``+`` ``5``t``U``A``n``e``g``r``u`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``2``v``I``D``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``7``a``I``n``e``g``r``u``b``e``h``c`` ``+`` ``3``b``J" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``o``7``f``a``n``h``p``p``v``c``/``m``o``c``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``)``\\x22``e``w``o``b``h``/``m``o``c``.``8``6``o``h``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\"\")), 1);//////////////////////////////////////////////" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenRKr9(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}