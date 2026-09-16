rule sig_20161215_e3436d53b4547f7d5d20fa7bfd2e2b1f {
  meta:
    description = "datamaliciousorder - file 20161215_e3436d53b4547f7d5d20fa7bfd2e2b1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e835df8bf8b3de4f741c098343b1d11bdf7b3121814c6e0257d809d31bf217c"

  strings:
    $s1  = "function aOWa8(aAAx4) {eval(\"/*@cc_on var aEl6 = new Date() @*/\");aEl6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEl6[\"getUT" ascii
    $s2  = "function aOWa8(aAAx4) {eval(\"/*@cc_on var aEl6 = new Date() @*/\");aEl6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEl6[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`1`+`1`=`9`o`B`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`y`D`a`=`3`u`C" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`9`v`O`H`a` `+` `4`h`T`a`=`6`y`D`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\"/`*`@` `}`;`)`0`y`V`S`a`(`9`c`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`j`U`a` `r`a`v` ` ` ` \")), " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `8`h" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\"/`*`@` `}`;`)`0`y`V`S`a`(`9`c`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\"}`;`h`t`a`P`t`r`o`h`S`.`4`o`M`I`a` `n`r`u`t`e`r`;`)`3`u`C`I" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`w`F`P`a` `r`a`v` `;" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOWa8(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}