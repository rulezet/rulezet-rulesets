rule sig_20161214_e475dd34fc757f940317e3de299d1025 {
  meta:
    description = "datamaliciousorder - file 20161214_e475dd34fc757f940317e3de299d1025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cd724ee9641e4cee91ad529274ee1d56edcf411aef5ec7c26d927dab60676ad"

  strings:
    $s1  = "function aAc7(aPVa2) {eval(\"/*@cc_on var aUh2 = new Date() @*/\");aUh2[\"setUTCSeconds\"](\"0\", \"20\");if (aUh2.getUTCMillise" ascii
    $s2  = "function aAc7(aPVa2) {eval(\"/*@cc_on var aUh2 = new Date() @*/\");aUh2[\"setUTCSeconds\"](\"0\", \"20\");if (aUh2.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"}`;`h`t`a`P`t`r`o`h`S`.`6`c`E`R`a` `n`r`u`t`e`r`;`)`4`g`Z`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"/`*`@` `}`;`3`k`Z`a` `n`r`u`t`e`r`;`}`;`)`6`y`D`N`a`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"/`*`@` `}`;`3`k`Z`a` `n`r`u`t`e`r`;`}`;`)`6`y`D`N`a`(`]`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`e`F`B`a` `r`a`v` ` ` ` \"))," ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"/`*`@` `}`;`1`b`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`h`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`z`B`a`=`4`g`Z`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`0` `=` `0`8`o`Q`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"/`*`@` `}`;`)`8`d`F`a`(`0`w`D`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`1`+`1`=`8`q`Y`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAc7(\";`1`+`1`=`8`q`Y`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}