rule sig_20161215_687a32bc894ac471f768a6746e72e46b {
  meta:
    description = "datamaliciousorder - file 20161215_687a32bc894ac471f768a6746e72e46b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f629d32c6fdf95d6806402cdea3fcf467cbf8736bca429c59ccde5b790fc2c15"

  strings:
    $s1  = "function aPv1(aDc0) {eval(\"/*@cc_on var aUTo0 = new Date() @*/\");aUTo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTo0[\"getU" ascii
    $s2  = "function aPv1(aDc0) {eval(\"/*@cc_on var aUTo0 = new Date() @*/\");aUTo0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTo0[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`y`Z`a`=`1`f`Q`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`1`+`1`=`3`i`O`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`y`K`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`f`P`Q`a` `r`a`v` ` ` ` \"))," ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\"}`;`h`t`a`P`t`r`o`h`S`.`0`i`Y`a` `n`r`u`t`e`r`;`)`1`f`Q`O`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\"/`*`@` `}`;`)`9`o`V`a`(`0`r`W`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `5`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`2`w`X`U`a` `+` `9`k`S`D`a`=`4`y`Z`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `5`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\";`1`+`1`=`3`i`O`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPv1(\"/`*`@` `}`;`8`r`E`a` `n`r`u`t`e`r`;`}`;`)`9`u`D`a`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}