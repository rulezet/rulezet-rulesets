rule sig_20161215_1704c03ec9be0d0a196643b23fda811a {
  meta:
    description = "datamaliciousorder - file 20161215_1704c03ec9be0d0a196643b23fda811a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a44d1d49bccee50217b0cf2b6465c8ad86660b78ba4ef40fd0364e5034f087c3"

  strings:
    $s1  = "function aQi8(aBRs5) {eval(\"/*@cc_on var aUk5 = new Date() @*/\");aUk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUk5[\"getUTC" ascii
    $s2  = "function aQi8(aBRs5) {eval(\"/*@cc_on var aUk5 = new Date() @*/\");aUk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUk5[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `8`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`x`X`a`;`)`2` `,`5`n`W`I`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\"/`*`@` `}`;`5`s`R`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`0` `=` `7`p`N`X`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\"/`*`@` `}`;`1`j`F`M`a` `n`r`u`t`e`r`;`}`;`)`5`d`S`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`n`K`a` `r`a`v` ` ` ` \")), 1" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`4`k`O`V`a` `+` `4`g`X`T`a`=`9`w`P`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`1`+`1`=`1`j`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\"/`*`@` `}`;`0`e`G`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`i`I`E`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `8`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQi8(\"/`*`@` `}`;`)`2`d`S`B`a`(`8`f`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}