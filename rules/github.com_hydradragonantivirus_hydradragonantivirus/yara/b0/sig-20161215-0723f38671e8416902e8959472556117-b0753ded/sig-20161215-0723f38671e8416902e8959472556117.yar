rule sig_20161215_0723f38671e8416902e8959472556117 {
  meta:
    description = "datamaliciousorder - file 20161215_0723f38671e8416902e8959472556117.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5363b3c1905b5996ca2c54afb8b93e5eea012824768e96a5d265d70d2d67174d"

  strings:
    $s1  = "function aVb0(aGs3) {eval(\"/*@cc_on var aJx6 = new Date() @*/\");aJx6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJx6[\"getUTCM" ascii
    $s2  = "function aVb0(aGs3) {eval(\"/*@cc_on var aJx6 = new Date() @*/\");aJx6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJx6[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`g`L`P`a`=`4`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`m`O`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"/`*`@` `}`;`3`y`V`a` `n`r`u`t`e`r`;`}`;`)`7`x`Q`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`f`P`a`;`)`2` `,`8`g`F`H`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `4`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `4`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"/`*`@` `}`;`)`3`p`D`C`a`(`1`b`K`I`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`4`y`G`a` `+` `1`e`X`a`=`4`g`L`P`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`f`P`a`;`)`2` `,`8`g`F`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`k`M`P`a` `n`r`u`t`e`r`;`)`4`o`K`H`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `4`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`m`O`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\"/`*`@` `}`;`3`s`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`1`+`1`=`3`g`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVb0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}