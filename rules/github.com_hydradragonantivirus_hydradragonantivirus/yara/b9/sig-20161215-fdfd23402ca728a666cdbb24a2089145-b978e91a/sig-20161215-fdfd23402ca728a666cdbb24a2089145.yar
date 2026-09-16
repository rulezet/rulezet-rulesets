rule sig_20161215_fdfd23402ca728a666cdbb24a2089145 {
  meta:
    description = "datamaliciousorder - file 20161215_fdfd23402ca728a666cdbb24a2089145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4792d84b05b04173ead0e1db9971671c27cd0963ebb79b1378d86f70732f325"

  strings:
    $s1  = "function aCf7(aKx8) {eval(\"/*@cc_on var aRo1 = new Date() @*/\");aRo1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRo1[\"getUTCM" ascii
    $s2  = "function aCf7(aKx8) {eval(\"/*@cc_on var aRo1 = new Date() @*/\");aRo1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRo1[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `6`t`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\"/`*`@` `}`;`8`x`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`1`+`1`=`8`w`Z`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`g`M`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`n`Y`a`;`)`2` `,`6`g`M`G`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`g`M`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`n`U`a`=`9`w`G`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`n`Y`a`;`)`2` `,`6`g`M`G`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`0` `=` `7`r`F`B`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\"/`*`@` `}`;`8`x`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCf7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`n`U`a`=`9`w`G`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}