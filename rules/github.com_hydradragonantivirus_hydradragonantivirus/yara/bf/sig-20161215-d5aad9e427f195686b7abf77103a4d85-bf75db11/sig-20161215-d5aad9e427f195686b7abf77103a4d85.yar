rule sig_20161215_d5aad9e427f195686b7abf77103a4d85 {
  meta:
    description = "datamaliciousorder - file 20161215_d5aad9e427f195686b7abf77103a4d85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85205a8aff8a6cee531da80abc6feb85bc8d4cb224fcc8ca41da15288d7dc208"

  strings:
    $s1  = "function aOGl9(aYk6) {eval(\"/*@cc_on var aEn6 = new Date() @*/\");aEn6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEn6[\"getUTC" ascii
    $s2  = "function aOGl9(aYk6) {eval(\"/*@cc_on var aEn6 = new Date() @*/\");aEn6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEn6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`)`8`n`N`L`a`(`6`w`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`2`v`Y`a` `+` `6`r`N`F`a`=`4`a`Q`U`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`0` `=` `5`n`I`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`)`8`n`N`L`a`(`6`w`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`q`F`E`a`;`)`2` `,`5`j`B`I`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`g`G`M`a` `r`a`v` ` ` ` \"))" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`6`k`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`Q`U`a`=`5`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`6`k`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`a`Q`U`a`=`5`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\"/`*`@` `}`;`3`j`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`j" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOGl9(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}