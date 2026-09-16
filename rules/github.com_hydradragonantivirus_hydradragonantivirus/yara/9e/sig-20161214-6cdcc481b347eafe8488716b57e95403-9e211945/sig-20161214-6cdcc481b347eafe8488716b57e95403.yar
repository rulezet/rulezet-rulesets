rule sig_20161214_6cdcc481b347eafe8488716b57e95403 {
  meta:
    description = "datamaliciousorder - file 20161214_6cdcc481b347eafe8488716b57e95403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce29902604b63bfd64721041f7c706dd07ae7910c27407bcf7505523ae2dbf3d"

  strings:
    $s1  = "function aHi2(aDa6) {eval(\"/*@cc_on var aIAr6 = new Date() @*/\");aIAr6[\"setUTCSeconds\"](\"0\", \"20\");if (aIAr6.getUTCMilli" ascii
    $s2  = "function aHi2(aDa6) {eval(\"/*@cc_on var aIAr6 = new Date() @*/\");aIAr6[\"setUTCSeconds\"](\"0\", \"20\");if (aIAr6.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`3`v`B`L`a` `+` `8`n`B`M`a`=`4`t`N`E`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`t`N`E`a`=`3`m`" ascii
    $s6  = ").toString(10) == \"20\") {var aZi4 = aDa6[\"split\"](\"`\"); return aZi4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`)`5`r`Y`Y`a`(`8`n`O`O`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`1`+`1`=`9`c`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`6`a`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`5`z`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`l`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`4`i`Z`a` `n`r`u`t`e`r`;`}`;`)`1`f`S`a`(`]`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\"/`*`@` `}`;`6`a`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHi2(\";`0` `=` `0`h`K`Q`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}