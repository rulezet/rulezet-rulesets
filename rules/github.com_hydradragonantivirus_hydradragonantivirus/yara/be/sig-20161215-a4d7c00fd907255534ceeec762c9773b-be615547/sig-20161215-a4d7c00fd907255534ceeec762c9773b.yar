rule sig_20161215_a4d7c00fd907255534ceeec762c9773b {
  meta:
    description = "datamaliciousorder - file 20161215_a4d7c00fd907255534ceeec762c9773b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9b2a5b986130da66c1b35ecd5527001b35d0ff8f1e6014373830cfaecdbbdd8"

  strings:
    $s1  = "function aHIb4(aPRj1) {eval(\"/*@cc_on var aECd2 = new Date() @*/\");aECd2[\"setUTCSeconds\"](\"0\", \"20\");if (aECd2.getUTCMil" ascii
    $s2  = "function aHIb4(aPRj1) {eval(\"/*@cc_on var aECd2 = new Date() @*/\");aECd2[\"setUTCSeconds\"](\"0\", \"20\");if (aECd2.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`1`b`Z`J`a` `n`r`u`t`e`r`;`}`;`)`9`r`E`V`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`j`I`X`a`;`)`2` `,`4`x`W`a`(`]" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`1`j`R`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`0` `=` `5`r`O`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`w`G`a`=`2`n`M" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`9`t`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`w" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`9`t`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`w" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`j`I`X`a`;`)`2` `,`4`x`W`a`(`]" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`)`1`c`L`a`(`0`d`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"}`;`h`t`a`P`t`r`o`h`S`.`2`v`I`I`a` `n`r`u`t`e`r`;`)`2`n`M`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHIb4(\"/`*`@` `}`;`)`1`c`L`a`(`0`d`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}