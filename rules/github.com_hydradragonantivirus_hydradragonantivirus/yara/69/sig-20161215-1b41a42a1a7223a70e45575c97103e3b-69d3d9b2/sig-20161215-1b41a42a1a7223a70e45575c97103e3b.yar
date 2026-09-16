rule sig_20161215_1b41a42a1a7223a70e45575c97103e3b {
  meta:
    description = "datamaliciousorder - file 20161215_1b41a42a1a7223a70e45575c97103e3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d27e15aa06718d2dbdf4e704bae4885a2a3d1d01cb59e43267b5a4d2fc4317a5"

  strings:
    $s1  = "function aTu4(aLSx3) {eval(\"/*@cc_on var aYSg5 = new Date() @*/\");aYSg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYSg5[\"get" ascii
    $s2  = "function aTu4(aLSx3) {eval(\"/*@cc_on var aYSg5 = new Date() @*/\");aYSg5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYSg5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"/`*`@` `}`;`)`1`l`L`a`(`4`u`A`N`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"/`*`@` `}`;`1`k`J`a` `n`r`u`t`e`r`;`}`;`)`9`g`G`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `3`h`O`O`a` `r`a`v` ` ` ` \"))," ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`0` `=` `6`b`Y`P`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`b`T`Y`a`;`)`2` `,`0`w`N`P`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`b`T`Y`a`;`)`2` `,`0`w`N`P`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`1`+`1`=`0`e`Q`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\"}`;`h`t`a`P`t`r`o`h`S`.`0`z`P`a` `n`r`u`t`e`r`;`)`6`d`Q`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTu4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`b`D`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}