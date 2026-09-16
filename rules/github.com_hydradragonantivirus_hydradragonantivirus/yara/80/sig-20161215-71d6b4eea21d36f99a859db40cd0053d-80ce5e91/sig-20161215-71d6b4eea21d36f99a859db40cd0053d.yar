rule sig_20161215_71d6b4eea21d36f99a859db40cd0053d {
  meta:
    description = "datamaliciousorder - file 20161215_71d6b4eea21d36f99a859db40cd0053d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f6b6c570df6f89e4f4da794ab9b9c741f47def17cf8ee4f0241aba4e2f3371"

  strings:
    $s1  = "function cheburgenDSg7(cheburgenGo8) {eval(\"/*@cc_on var cheburgenTNw2 = new Date() @*/\");cheburgenTNw2[\"setUTC\"+\"Seconds\"" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``1``+``1``=``3``a``N``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``0`` ``=`` ``1``c``F``n``e``g``r``u``b``e``h``c`` ``r" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``6``u``U``n``e``g``r``u``b``e``h``c`` " ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``\\x22``\\x22`` ``+`` ``1``w``O``n``e``g``r``u``b`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``r``B``n``e" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``8``o``G``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``\\x22``7``g``z``e``y``r``2``v``p``/``m``o``c``.``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``\\x22``2``e``j``3``p``a``q``/``m``o``c``.``e``s``" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"\")), 1);//////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``9``a``T``V``n``e``g``r``u``b``e``h``c`` ``+`` ``7``x" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``s``V``n" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``5``r``B``n``e" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenDSg7(\";``0`` ``=`` ``1``c``F``n``e``g``r``u``b``e``h``c`` ``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}