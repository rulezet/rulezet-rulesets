rule sig_20161216_bf21dfdd23ecb2cde6c4820da2cc6adf {
  meta:
    description = "datamaliciousorder - file 20161216_bf21dfdd23ecb2cde6c4820da2cc6adf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "474927e685ab909cef10e2551959dd2357d75faf69867eda51cd273666c73fdf"

  strings:
    $s1  = "function methPAl0(methYk6) {eval(\"/*@cc_on var methVn3 = new Date() @*/\");methVn3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (m" ascii
    $s2  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``Q``Y``h``t``e`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``t``F``D`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``)``3``g``D``h``t``e``m``(``2``n``U``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"}``;``h``t``a``P``t``r``o``h``S``.``4``l``Q``Y``h``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``7``a``Y``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``7``a``Y``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``\\x22``g``j``g``i``0``/``m``o``c``.``g``n``o``s``n" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``3``y``K``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``\\x22``x``g``4``x``z``c``b``i``s``5``/``k``u``.``o" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\"/``*``@`` ``}``;``)``3``g``D``h``t``e``m``(``2``n``U``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``5``k``S``h``t``e``m`` ``+`` ``3``f``B``h``t``e``m``=`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methPAl0(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}