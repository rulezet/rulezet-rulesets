rule sig_20161216_4ad644294b986262d6ffa349beb58ce8 {
  meta:
    description = "datamaliciousorder - file 20161216_4ad644294b986262d6ffa349beb58ce8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c47e8ece709877c49984e12984abda2fbb1741157c1d073d5761c8de7b11b29"

  strings:
    $s1  = "function methAVu4(methXHk4) {eval(\"/*@cc_on var methTXn7 = new Date() @*/\");methTXn7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if" ascii
    $s2  = "[\"getUTCMilliseconds\"]()[\"toString\"](10) == \"20\") {var methWKi3 = methXHk4[\"sp\"+\"lit\"](\"``\"); return methWKi3[\"reve" ascii
    $s3  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``q``F``h``t`" ascii
    $s4  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``\\x22``7``g``c``s``k``/``m``o``c``.``3``2``1``g``n" ascii
    $s5  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``3``i``K``W``h``t``e``m`` ``n``r``u``t`" ascii
    $s6  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``8``u``S``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s7  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``\\x22``P``T``T``H``L``M``X``.``2``L``M``X``S``M``" ascii
    $s8  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii
    $s9  = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``(``y``a``r``r``A`` ``w``e``n`` ``=`` ``1``y``O``h`" ascii
    $s10 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``'``/``%``P``M``E``T``%``'``(``]``'``s``g``n``i``r`" ascii
    $s11 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``\\x22``k``\\x22`` ``+`` ``\\x22``z``.``\\x22`` ``+`` " ascii
    $s12 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii
    $s13 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"}``;``h``t``a``P``t``r``o``h``S``.``0``s``R``h``t``e``m`" ascii
    $s14 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``)``\\x22``4``5``n``b``o``n``j``/``m``o``c``.``a``f``o" ascii
    $s15 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``8``u``S``h``t``e``m`` ``n``r``u``t``e`" ascii
    $s16 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``)``(``e``s``o``l``c``.``3``q``F``h``t`" ascii
    $s17 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"\"))), 1);//////////////////////////////////////////////" ascii
    $s18 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``4``k``H``X``h``t``e``m`` ``n``r``u``t`" ascii
    $s19 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\";``1``+``1``=``4``f``N``h``t``e``m`` ``r``a``v``;``)``" ascii
    $s20 = "var v_bbb = (1, new Function(\"b\", \"return b;\"), eval((1, methAVu4(\"/``*``@`` ``}``;``}``;``e``u``n``i``t``n``o``c``{`` ``)`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}