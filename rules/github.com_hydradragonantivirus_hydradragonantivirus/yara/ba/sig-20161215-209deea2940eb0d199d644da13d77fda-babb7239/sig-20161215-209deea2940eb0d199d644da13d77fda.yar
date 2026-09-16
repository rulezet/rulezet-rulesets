rule sig_20161215_209deea2940eb0d199d644da13d77fda {
  meta:
    description = "datamaliciousorder - file 20161215_209deea2940eb0d199d644da13d77fda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a546c6ba132d1b23d7fb2113623a4bdba85fc74b8f5d9ce4775b3a2fe5225bd"

  strings:
    $s1  = "function aUOm2(aDVa1) {eval(\"/*@cc_on var aJq6 = new Date() @*/\");aJq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJq6[\"getUT" ascii
    $s2  = "function aUOm2(aDVa1) {eval(\"/*@cc_on var aJq6 = new Date() @*/\");aJq6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJq6[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"/`*`@` `}`;`6`c`Z`a` `n`r`u`t`e`r`;`}`;`)`1`i`T`a`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"/`*`@` `}`;`1`a`V`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`u`B`D`a` `r`a`v` ` ` ` \"))" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"/`*`@` `}`;`8`n`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"/`*`@` `}`;`8`n`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`t`R`V`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUOm2(\";`1`+`1`=`8`i`P`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}