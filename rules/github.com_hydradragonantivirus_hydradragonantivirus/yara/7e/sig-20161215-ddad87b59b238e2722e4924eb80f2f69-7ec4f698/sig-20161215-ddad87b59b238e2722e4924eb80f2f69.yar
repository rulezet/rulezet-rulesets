rule sig_20161215_ddad87b59b238e2722e4924eb80f2f69 {
  meta:
    description = "datamaliciousorder - file 20161215_ddad87b59b238e2722e4924eb80f2f69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3609d4ac1773cdc5fe68f97b54535e3d7786fb7e984603fc9fa5b3af82c88fbc"

  strings:
    $s1  = "function aMm8(aTUb6) {eval(\"/*@cc_on var aMi0 = new Date() @*/\");aMi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMi0[\"getUTC" ascii
    $s2  = "function aMm8(aTUb6) {eval(\"/*@cc_on var aMi0 = new Date() @*/\");aMi0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMi0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\"/`*`@` `}`;`6`b`U`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`f`V`a`=`2`r`W`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`t`N`Y`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `3`i`P`a`(`h`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`d`G`a` `r`a`v` ` ` ` \")), 1" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `3`i`P`a`(`h`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "s\"]()[\"toString\"](10) == \"20\") {var aTa0 = aTUb6[\"split\"](\"`\"); return aTa0[\"reverse\"]().join(\"\");} else return \"" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `3`i`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`y`L`a` `n`r`u`t`e`r`;`)`2`r`W`X`a`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`1`+`1`=`0`a`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`r`G`D`a`;`)`2` `,`9`p`Y`P`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`r`G`D`a`;`)`2` `,`9`p`Y`P`a`(`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMm8(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}