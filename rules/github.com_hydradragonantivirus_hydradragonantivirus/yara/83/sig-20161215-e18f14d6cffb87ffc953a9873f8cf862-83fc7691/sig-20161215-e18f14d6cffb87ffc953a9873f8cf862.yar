rule sig_20161215_e18f14d6cffb87ffc953a9873f8cf862 {
  meta:
    description = "datamaliciousorder - file 20161215_e18f14d6cffb87ffc953a9873f8cf862.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "411a2d103d7911309958ba6bdd695b0ad2613474d583a94ae17fdfb2705f3853"

  strings:
    $s1  = "function aPZf8(aYAr7) {eval(\"/*@cc_on var aXd4 = new Date() @*/\");aXd4[\"setUTCSeconds\"](\"0\", \"20\");if (aXd4.getUTCMillis" ascii
    $s2  = "function aPZf8(aYAr7) {eval(\"/*@cc_on var aXd4 = new Date() @*/\");aXd4[\"setUTCSeconds\"](\"0\", \"20\");if (aXd4.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`y`O`O`a`;`)`2` `,`7`y`T`a`(`]" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"}`;`h`t`a`P`t`r`o`h`S`.`8`v`Q`K`a` `n`r`u`t`e`r`;`)`0`s`F`L" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`0` `=` `7`x`T`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`y`O`O`a`;`)`2` `,`7`y`T`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`a`M`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"/`*`@` `}`;`4`w`R`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\"/`*`@` `}`;`)`4`y`L`a`(`0`v`R`R`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`a`M`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPZf8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}