rule sig_20161216_53715f4c59b50b011bd12d067ca52a71 {
  meta:
    description = "datamaliciousorder - file 20161216_53715f4c59b50b011bd12d067ca52a71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe3ac117794b03155ce2a4156e49777f4167097df8712d60023e499957b0ec9"

  strings:
    $s1  = "function cheburgenZGb6(cheburgenEDx6) {eval(\"/*@cc_on var cheburgenKy4 = new Date() @*/\");cheburgenKy4[\"setUTC\"+\"Seconds\"]" ascii
    $s2  = "\"20\");if (cheburgenKy4[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var cheburgenEm6 = cheburgenEDx6[\"split\"](\"`" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``8``q``J``P``n" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``\\x22``n``v``f``l``i``/``m``o``c``.``a``k``s``n``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``\\x22``i``t``v``j``a``7``a``b``l``/``m``o``c``.``" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``\\x22``X``J``j``u``b``1``g``I``x``1``y``m``N``O``l``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``7``y``Y``n``e``g``r``u``b``e``h``c`` ``+`` ``7``x``Q" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``1``n``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``3``n``V``N" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``6``x``D``E``n``e``g``r``u``b``e``h``c" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"}``;``h``t``a``P``t``r``o``h``S``.``3``w``R``R``n``e``g" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``6``m``E``n``e``g``r``u``b``e``h``c`` " ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``)``\\x22``h``s``c``p``j``v``u``t``l``j``/``t``e``n``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\"/``*``@`` ``}``;``1``n``R``n``e``g``r``u``b``e``h``c`` " ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval(cheburgenZGb6(\";``1``+``1``=``5``j``Y``Q``n``e``g``r``u``b``e``h``c`` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}