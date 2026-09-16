rule sig_20161215_0d8d57f0ed27cf8fc31af26863727e51 {
  meta:
    description = "datamaliciousorder - file 20161215_0d8d57f0ed27cf8fc31af26863727e51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49c14b19c050209487715fa59286baaffc1b9dc2f453cd930bac347a54e9689e"

  strings:
    $s1  = "function aTNs0(aXh9) {eval(\"/*@cc_on var aFKc2 = new Date() @*/\");aFKc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFKc2[\"get" ascii
    $s2  = "function aTNs0(aXh9) {eval(\"/*@cc_on var aFKc2 = new Date() @*/\");aFKc2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFKc2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `9" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`0`x`i`1`u`m`j`/`u`r`.`u`g`n`e`l`f`e`\\x22` `+` `9" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`w`P`D`a`;`)`2` `,`2`w`A`I`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`n`T`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"/`*`@` `}`;`5`k`K`a` `n`r`u`t`e`r`;`}`;`)`8`g`N`a`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`1`+`1`=`3`w`S`Q`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`u`P`Q`a`=`1`t" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"/`*`@` `}`;`9`h`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"/`*`@` `}`;`)`9`o`A`a`(`5`c`M`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTNs0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`s`L`P`a` `n`r`u`t`e`r`;`)`1`t`L`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}