rule sig_20161215_17685274a274bba686f45492a2537d90 {
  meta:
    description = "datamaliciousorder - file 20161215_17685274a274bba686f45492a2537d90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7e61e4a1d8fa2b662024ad51aed5c6d39598050fd621a7c883619963abbe2fb"

  strings:
    $s1  = "function aDOi0(aCKl4) {eval(\"/*@cc_on var aQg3 = new Date() @*/\");aQg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQg3[\"getUT" ascii
    $s2  = "function aDOi0(aCKl4) {eval(\"/*@cc_on var aQg3 = new Date() @*/\");aQg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQg3[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`p`Z`G`a` `r`a`v` ` ` ` \"))" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`1`+`1`=`0`o`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`d`K`D`a` `n`r`u`t`e`r`;`)`8`k`M`J" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"/`*`@` `}`;`4`l`K`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "ds\"]()[\"toString\"](10) == \"20\") {var aVi1 = aCKl4[\"split\"](\"`\"); return aVi1[\"reverse\"]().join(\"\");} else return \"" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"/`*`@` `}`;`4`l`K`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"/`*`@` `}`;`)`4`l`F`a`(`7`f`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`v`P`a`;`)`2` `,`7`w`I`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`v`P`a`;`)`2` `,`7`w`I`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`i`L`B`a` `r`a`v` `;" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`i`L`B`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOi0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`d`K`D`a` `n`r`u`t`e`r`;`)`8`k`M`J" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}