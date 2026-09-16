rule sig_20161214_4eb03d3087b90ad2a98b3cc705789cd7 {
  meta:
    description = "datamaliciousorder - file 20161214_4eb03d3087b90ad2a98b3cc705789cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4ec3c6b01d0f0cea922976ed7584ed07f9ba9a8bea7280f9a1bb8b7603d2ceb"

  strings:
    $s1  = "function aKLi2(aSf5) {eval(\"/*@cc_on var aBJc8 = new Date() @*/\");aBJc8[\"setUTCSeconds\"](\"0\", \"20\");if (aBJc8.getUTCMill" ascii
    $s2  = "function aKLi2(aSf5) {eval(\"/*@cc_on var aBJc8 = new Date() @*/\");aBJc8[\"setUTCSeconds\"](\"0\", \"20\");if (aBJc8.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `0`p`I" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"/`*`@` `}`;`6`w`L`a` `n`r`u`t`e`r`;`}`;`)`5`f`M`E`a`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`s`X`a` `n`r`u`t`e`r`;`)`0`y`B`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`o`Z`P`a`;`)`2` `,`9`h`W`X`a`(" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`1`+`1`=`6`y`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "().toString(10) == \"20\") {var aLw6 = aSf5[\"split\"](\"`\"); return aLw6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`v`M`a`=`0`y`B" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`v`M`a`=`0`y`B" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"/`*`@` `}`;`)`8`w`Y`V`a`(`4`j`V`C`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKLi2(\"/`*`@` `}`;`3`m`S`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}