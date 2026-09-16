rule sig_20161215_700b5cb9802bf13ad9ae9d03dfee9681 {
  meta:
    description = "datamaliciousorder - file 20161215_700b5cb9802bf13ad9ae9d03dfee9681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29b1bec7f205a3110170603b2cacc1cf4093f8e9bb8740cd431c6eb58f135ad0"

  strings:
    $s1  = "function aHCq1(aUPi2) {eval(\"/*@cc_on var aPw6 = new Date() @*/\");aPw6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPw6[\"getUT" ascii
    $s2  = "function aHCq1(aUPi2) {eval(\"/*@cc_on var aPw6 = new Date() @*/\");aPw6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPw6[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`e`P`O`a` `r`a`v` `;" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`9`j`O`T`a` `n`r`u`t`e`r`;`}`;`)`8`b`V`V`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`0` `=` `5`y`P`Q`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`0`i`H`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`q`E`X`a`;`)`2` `,`2`n`U`O`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`n`N`N`a`=`4`f" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`1`p`a`y`d`/`s`e`.`r`a`c`i`f`a`\\x22` `+` `8`k`M`a" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`s`K`K`a` `r`a`v` ` ` ` \"))" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`9`j`O`T`a` `n`r`u`t`e`r`;`}`;`)`8`b`V`V`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHCq1(\"/`*`@` `}`;`2`i`P`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}