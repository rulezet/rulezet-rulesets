rule sig_20161215_3a9ff8e689b0506ce1e1159969247ffe {
  meta:
    description = "datamaliciousorder - file 20161215_3a9ff8e689b0506ce1e1159969247ffe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b4b1958126a36a7040e43030fa492e95487af14275a3ae5bc3d2e9d849fbdfb"

  strings:
    $s1  = "function aOUe4(aNWa6) {eval(\"/*@cc_on var aSs7 = new Date() @*/\");aSs7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSs7[\"getUT" ascii
    $s2  = "function aOUe4(aNWa6) {eval(\"/*@cc_on var aSs7 = new Date() @*/\");aSs7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSs7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`\\x22`x`x`1`p`l`e`n`v`d`/`m`o`c`.`t`s`s`e`w`-`a`d`n`a`f" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`n`B`Y`a` `r`a`v` ` ` ` \"))" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`1`+`1`=`6`n`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`6`a`W`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`k`L`H`a`=`2`g" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`r`C`a`;`)`2` `,`9`y`O`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`r`C`a`;`)`2` `,`9`y`O`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`k`L`H`a`=`2`g" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`6`a`W`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\";`1`+`1`=`6`n`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`)`9`q`R`a`(`7`r`O`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"}`;`h`t`a`P`t`r`o`h`S`.`0`c`J`a` `n`r`u`t`e`r`;`)`2`g`V`H`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOUe4(\"/`*`@` `}`;`5`g`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}