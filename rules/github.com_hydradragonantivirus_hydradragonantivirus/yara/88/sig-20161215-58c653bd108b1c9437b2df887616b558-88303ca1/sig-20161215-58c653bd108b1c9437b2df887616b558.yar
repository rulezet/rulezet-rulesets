rule sig_20161215_58c653bd108b1c9437b2df887616b558 {
  meta:
    description = "datamaliciousorder - file 20161215_58c653bd108b1c9437b2df887616b558.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97f3d1c9f3b0507f85286c1e23be788c297288e7911dffe39ff9d3e218370da2"

  strings:
    $s1  = "function aTo3(aWRc6) {eval(\"/*@cc_on var aDXk2 = new Date() @*/\");aDXk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDXk2[\"get" ascii
    $s2  = "function aTo3(aWRc6) {eval(\"/*@cc_on var aDXk2 = new Date() @*/\");aDXk2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDXk2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`6`c`R`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`)`4`r`E`I`a`(`2`i`P`H`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`)`4`r`E`I`a`(`2`i`P`H`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`7`z`F`N`a` `n`r`u`t`e`r`;`}`;`)`8`a`J`a`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`7`o`B`a` `+` `5`d`I`I`a`=`5`p`U`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`p`U`a`=`9`h`F`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`6`c`R`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`o`B`E`a`;`)`2` `,`8`j`R`Q`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`t`Y`A`a` `r`a`v` ` ` ` \"))," ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`e`C`T`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTo3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`e`C`T`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}