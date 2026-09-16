rule sig_20161215_791ade7475a58a34355e2ce9d1fc376f {
  meta:
    description = "datamaliciousorder - file 20161215_791ade7475a58a34355e2ce9d1fc376f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea6cdc5a5e185b3a1cdca2fa9f6be9357c3a4fa3affd234921054cc72190cbed"

  strings:
    $s1  = "function aJx3(aPm6) {eval(\"/*@cc_on var aHDl5 = new Date() @*/\");aHDl5[\"setUTCSeconds\"](\"0\", \"20\");if (aHDl5.getUTCMilli" ascii
    $s2  = "function aJx3(aPm6) {eval(\"/*@cc_on var aHDl5 = new Date() @*/\");aHDl5[\"setUTCSeconds\"](\"0\", \"20\");if (aHDl5.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\"}`;`h`t`a`P`t`r`o`h`S`.`8`o`I`a` `n`r`u`t`e`r`;`)`6`t`Y`L`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`u`D`a` `r`a`v` ` ` ` \")), 1" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`1`+`1`=`7`f`Z`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`1`+`1`=`7`f`Z`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`9`w`C`a` `+` `3`k`F`a`=`6`u`B`I`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\"/`*`@` `}`;`2`t`W`a` `n`r`u`t`e`r`;`}`;`)`3`k`L`R`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\"/`*`@` `}`;`)`9`t`V`H`a`(`8`g`V`B`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s17 = ").toString(10) == \"20\") {var aWt2 = aPm6[\"split\"](\"`\"); return aWt2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`c`H`K`a`;`)`2` `,`7`t`S`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJx3(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}