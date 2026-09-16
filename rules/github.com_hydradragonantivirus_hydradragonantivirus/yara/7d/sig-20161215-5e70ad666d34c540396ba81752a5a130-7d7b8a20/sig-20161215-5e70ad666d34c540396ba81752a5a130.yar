rule sig_20161215_5e70ad666d34c540396ba81752a5a130 {
  meta:
    description = "datamaliciousorder - file 20161215_5e70ad666d34c540396ba81752a5a130.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c46bb29dc79797c1d7d37b03f9791c6f523f237169660173caaad14fdc0665a8"

  strings:
    $s1  = "function aTSa7(aEXd1) {eval(\"/*@cc_on var aTs3 = new Date() @*/\");aTs3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTs3[\"getUT" ascii
    $s2  = "function aTSa7(aEXd1) {eval(\"/*@cc_on var aTs3 = new Date() @*/\");aTs3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aTs3[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `1`j" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`7`r`R`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`m" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`0` `=` `0`e`S`A`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `1`j`P`F`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`7`r`R`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`m" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`c`K`R`a` `r`a`v` `;" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`x`M`a` `n`r`u`t`e`r`;`)`4`u`Y`a`(" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`4`f`F`I`a` `n`r`u`t`e`r`;`}`;`)`6`g`L`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`4`f`F`I`a` `n`r`u`t`e`r`;`}`;`)`6`g`L`a`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`7`b`S`M`a` `+` `5`f`L`a`=`7`e`N`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTSa7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`x`M`a` `n`r`u`t`e`r`;`)`4`u`Y`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}