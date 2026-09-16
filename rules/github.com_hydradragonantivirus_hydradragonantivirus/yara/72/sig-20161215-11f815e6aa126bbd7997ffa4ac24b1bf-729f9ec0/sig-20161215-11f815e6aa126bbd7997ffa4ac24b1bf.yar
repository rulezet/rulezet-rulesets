rule sig_20161215_11f815e6aa126bbd7997ffa4ac24b1bf {
  meta:
    description = "datamaliciousorder - file 20161215_11f815e6aa126bbd7997ffa4ac24b1bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0b9d27bfc6633bb26c8e10ce4c5b04ea8b36cc84fa18ce08c84656eb8624351"

  strings:
    $s1  = "function aTZx0(aGBw3) {eval(\"/*@cc_on var aOBc4 = new Date() @*/\");aOBc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOBc4[\"ge" ascii
    $s2  = "function aTZx0(aGBw3) {eval(\"/*@cc_on var aOBc4 = new Date() @*/\");aOBc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOBc4[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`7`b`K`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`)`8`u`J`Y`a`(`5`h`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`i`T`X`a` `r`a`v` ` ` ` \"))" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`3`w`B`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`b`C`a`;`)`2` `,`9`r`R`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"}`;`h`t`a`P`t`r`o`h`S`.`1`q`S`A`a` `n`r`u`t`e`r`;`)`4`p`F`B" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`)`8`u`J`Y`a`(`5`h`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`7`b`K`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`9`t`O`a` `+` `9`d`S`B`a`=`1`s`V`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTZx0(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}