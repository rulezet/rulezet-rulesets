rule sig_20161216_f7e6513cf3d1ea33a39d896924de2f25 {
  meta:
    description = "datamaliciousorder - file 20161216_f7e6513cf3d1ea33a39d896924de2f25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db64d0b49d59839c754222d98f4574c7dee6c5176ec066e6f130d57e092798"

  strings:
    $s1  = "\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methUMx0 = methQOa1[\"sp\"+\"lit\"](\"``\"); return methUMx0[\"rever" ascii
    $s2  = "function methRv2(methQOa1) {eval(\"/*@cc_on var methUEm1 = new Date() @*/\");methUEm1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if " ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r``" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``o``3``h``j``z``s``u``7``a``/``t``e``n``.``g`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``9``n``M``h``t``e``m`` ``+`` ``2``z``A``h``t``e``m``=``" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``i``y``c``2``y``k``7``u``/``l``p``.``o``i``d`" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\"/``*``@`` ``}``;``8``z``R``M``h``t``e``m`` ``n``r``u``t``" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)``" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``k``v``x``u``i``z``o``k``q``x``/``h``p``.``l`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``n``G``W``" ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``\\x22``P``S``Y``a``a``L``P``Q``x``t``n``x``F``A``g``M`" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` `" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\"/``*``@`` ``}``;``1``a``O``Q``h``t``e``m`` ``n``r``u``t``" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\"\"))), 1);///////////////////////////////////////////////" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\"}``;``h``t``a``P``t``r``o``h``S``.``1``g``T``J``h``t``e``" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``9``n``M``h``t``e``m`` ``+`` ``2``z``A``h``t``e``m``=``" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``v``d``g``j``k``b``a``c``y``/``m``o``c``.``s`" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methRv2(\";``)``\\x22``l``l``e``h``S``.``t``p``i``r``c``S``W``\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}