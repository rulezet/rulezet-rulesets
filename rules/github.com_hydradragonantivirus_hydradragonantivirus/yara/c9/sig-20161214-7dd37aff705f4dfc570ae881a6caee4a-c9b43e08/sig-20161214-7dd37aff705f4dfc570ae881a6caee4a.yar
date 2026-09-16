rule sig_20161214_7dd37aff705f4dfc570ae881a6caee4a {
  meta:
    description = "datamaliciousorder - file 20161214_7dd37aff705f4dfc570ae881a6caee4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b7ec3ac701256bbd073ed22584aea1cf1dabf43b0b72883f70970510f9723af"

  strings:
    $s1  = "function aKm6(aHc3) {eval(\"/*@cc_on var aUDp3 = new Date() @*/\");aUDp3[\"setUTCSeconds\"](\"0\", \"20\");if (aUDp3.getUTCMilli" ascii
    $s2  = "function aKm6(aHc3) {eval(\"/*@cc_on var aUDp3 = new Date() @*/\");aUDp3[\"setUTCSeconds\"](\"0\", \"20\");if (aUDp3.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`h`L`L`a`=`2`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`3`c`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`1`w`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`2`k`K`B`a` `+` `7`y`B`a`=`8`h`L`L`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`9`p`D`a` `n`r`u`t`e`r`;`}`;`)`5`m`C`a`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"}`;`h`t`a`P`t`r`o`h`S`.`5`s`I`a` `n`r`u`t`e`r`;`)`2`c`R`N`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`1`+`1`=`2`x`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`n`W`L`a`;`)`2` `,`7`h`C`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = ").toString(10) == \"20\") {var aDp9 = aHc3[\"split\"](\"`\"); return aDp9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKm6(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}