rule sig_20161214_b2721cd905e184c1624c0199fd3bca14 {
  meta:
    description = "datamaliciousorder - file 20161214_b2721cd905e184c1624c0199fd3bca14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f2b2c8d8d155282552e6a1ea4b166c20f8acbc48a1859820b3f307a53b4b33c"

  strings:
    $s1  = "function aGd6(aGKm9) {eval(\"/*@cc_on var aHIm3 = new Date() @*/\");aHIm3[\"setUTCSeconds\"](\"0\", \"20\");if (aHIm3.getUTCMill" ascii
    $s2  = "function aGd6(aGKm9) {eval(\"/*@cc_on var aHIm3 = new Date() @*/\");aHIm3[\"setUTCSeconds\"](\"0\", \"20\");if (aHIm3.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"/`*`@` `}`;`8`s`Z`B`a` `n`r`u`t`e`r`;`}`;`)`4`b`O`a`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`m`I`H`a`=`9`x`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`1`+`1`=`1`e`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"/`*`@` `}`;`9`m`K`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`1`+`1`=`1`e`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"/`*`@` `}`;`9`m`K`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`0` `=` `4`b`L`Z`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"}`;`h`t`a`P`t`r`o`h`S`.`4`e`T`F`a` `n`r`u`t`e`r`;`)`9`x`P`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `1`n`V`V`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `1`n`V`V`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"\")), 1);" fullword ascii
    $s19 = "().toString(10) == \"20\") {var aBZs8 = aGKm9[\"split\"](\"`\"); return aBZs8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGd6(\"/`*`@` `}`;`8`s`Z`B`a` `n`r`u`t`e`r`;`}`;`)`4`b`O`a`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}