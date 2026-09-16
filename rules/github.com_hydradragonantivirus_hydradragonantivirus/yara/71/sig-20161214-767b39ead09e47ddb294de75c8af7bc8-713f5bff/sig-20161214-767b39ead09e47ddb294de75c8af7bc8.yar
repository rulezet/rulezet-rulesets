rule sig_20161214_767b39ead09e47ddb294de75c8af7bc8 {
  meta:
    description = "datamaliciousorder - file 20161214_767b39ead09e47ddb294de75c8af7bc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a2ca0781fa117de63b565d4ed8947f8360de66725e3ea5c1c69a8c6c6528b2"

  strings:
    $s1  = "function aMWx4(aCIm5) {eval(\"/*@cc_on var aMSa3 = new Date() @*/\");aMSa3[\"setUTCSeconds\"](\"0\", \"20\");if (aMSa3.getUTCMil" ascii
    $s2  = "function aMWx4(aCIm5) {eval(\"/*@cc_on var aMSa3 = new Date() @*/\");aMSa3[\"setUTCSeconds\"](\"0\", \"20\");if (aMSa3.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`g`Z`a`=`1`x`W" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`0`y`I`G`a` `n`r`u`t`e`r`;`}`;`)`5`m`O`a`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`0`y`I`G`a` `n`r`u`t`e`r`;`}`;`)`5`m`O`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"}`;`h`t`a`P`t`r`o`h`S`.`1`y`M`W`a` `n`r`u`t`e`r`;`)`1`x`W`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`4`m`K`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`q`Y`a` `r`a`v` ` ` ` \")), " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`5`m`I`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMWx4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`p`X`S`a`;`)`2` `,`1`f`L`a`(`]" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}