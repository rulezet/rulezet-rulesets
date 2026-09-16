rule sig_20161214_f53e4d091325a217b4fe7876861eaa16 {
  meta:
    description = "datamaliciousorder - file 20161214_f53e4d091325a217b4fe7876861eaa16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b0a9ddf61ed5253f8f6f898345a095cbe6359616880f3467e8b76be0025428a"

  strings:
    $s1  = "function aAFa7(aXMe0) {eval(\"/*@cc_on var aIDi0 = new Date() @*/\");aIDi0[\"setUTCSeconds\"](\"0\", \"20\");if (aIDi0.getUTCMil" ascii
    $s2  = "function aAFa7(aXMe0) {eval(\"/*@cc_on var aIDi0 = new Date() @*/\");aIDi0[\"setUTCSeconds\"](\"0\", \"20\");if (aIDi0.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`)`8`g`T`U`a`(`0`u`S`F`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`x`Z`a`=`0`i`L" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`0`s`H`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`0`e`M`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`t`E`a` `n`r`u`t`e`r`;`)`0`i`L`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`7`y`E`a` `n`r`u`t`e`r`;`}`;`)`1`h`R`A`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`5`w`Y`F`a` `+` `0`s`B`O`a`=`2`x`Z`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `6" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAFa7(\";`1`+`1`=`4`a`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}