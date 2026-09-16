rule sig_20161216_bd4226196598242841fdf526bd78c44c {
  meta:
    description = "datamaliciousorder - file 20161216_bd4226196598242841fdf526bd78c44c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "065588a82bbb1cafa3788effe8f693a885d949fffdcd8ec690340b084583e48b"

  strings:
    $s1  = "function methZYb3(methAZj7) {eval(\"/*@cc_on var methTCk8 = new Date() @*/\");methTCk8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methSZz8 = methAZj7[\"sp\"+\"lit\"](\"``\"); return methSZz8[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"/``*``@`` ``}``;``4``g``D``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x2" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``\\x22``q``d``i``x``o``k``v``h``/``t``e``n``.``e``r" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``\\x22``/``\\x22``+``\\x22``/``\\x22``+``\\x22``:``\\x" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"/``*``@`` ``}``;``)``6``m``E``G``h``t``e``m``(``9``g``P`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``0``l``W``C``h``t``e``m`` ``+`` ``2``x``E``E``h``t``e`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"}``;``h``t``a``P``t``r``o``h``S``.``1``h``V``h``t``e``m`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``1``p``V``E``h`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``\\x22``0``g``d``u``k``c``j``/``t``i``.``i``l``i``b" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"/``*``@`` ``}``;``4``g``D``G``h``t``e``m`` ``n``r``u``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\"/``*``@`` ``}``;``8``z``Z``S``h``t``e``m`` ``n``r``u``t`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``2``d``A``h`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``0``l``W``C``h``t``e``m`` ``+`` ``2``x``E``E``h``t``e`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methZYb3(\";``)``\\x22``c``s``f``n``q``h``/``m``o``c``.``l``l``i``r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}