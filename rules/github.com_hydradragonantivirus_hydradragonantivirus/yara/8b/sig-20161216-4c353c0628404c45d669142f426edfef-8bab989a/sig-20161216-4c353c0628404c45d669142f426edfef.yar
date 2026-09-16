rule sig_20161216_4c353c0628404c45d669142f426edfef {
  meta:
    description = "datamaliciousorder - file 20161216_4c353c0628404c45d669142f426edfef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b10d8b843cda2d2567c41b21a2fc97da6521de07b80ab8f1c961ce454e8c268"

  strings:
    $s1  = "function cheburgenNDv3(cheburgenDCb3) {eval(\"/*@cc_on var cheburgenBBm0 = new Date() @*/\");cheburgenBBm0[\"setUTC\"+\"Seconds" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``1``+``1``=``5``x``G``K``n``e``g``r``u``b``e``h``c`` " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"\")), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"/``*``@`` ``}``;``4``g``C``n``e``g``r``u``b``e``h``c`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``w``A``A``n``e``g" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"/``*``@`` ``}``;``)``1``h``L``n``e``g``r``u``b``e``h``c" ascii
    $s12 = "urn cheburgenCg4[\"reverse\"]().join(\"\");} else return \"\";};" fullword ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``)``\\x22``t``i``n``w``h``j``c``/``m``o``c``.``s``e``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"/``*``@`` ``}``;``)``1``h``L``n``e``g``r``u``b``e``h``c" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\"/``*``@`` ``}``;``3``b``C``D``n``e``g``r``u``b``e``h``c" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``0`` ``=`` ``0``c``A``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``8``g``Z``W``n``e``g``r``u``b``e``h``c`` ``+`` ``9``t" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``)``\\x22``q``y``4``a``c``/``e``d``.``u``4``y``z``a``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenNDv3(\";``)``\\x22``1``5``h``t``e``n``s``c``/``r``b``.``g``r``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}