rule sig_20161215_b3a8707890c82eca5a5c5b5cedebc33c {
  meta:
    description = "datamaliciousorder - file 20161215_b3a8707890c82eca5a5c5b5cedebc33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa4c955a545236b82fe7a43259afccb27fa776cf51a8f244f0b1cb395901435d"

  strings:
    $s1  = "function aNJk7(aTk5) {eval(\"/*@cc_on var aYp9 = new Date() @*/\");aYp9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYp9[\"getUTC" ascii
    $s2  = "function aNJk7(aTk5) {eval(\"/*@cc_on var aYp9 = new Date() @*/\");aYp9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYp9[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`f`U`H`a`=`8`b" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"/`*`@` `}`;`)`7`j`D`P`a`(`6`v`W`Q`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"}`;`h`t`a`P`t`r`o`h`S`.`7`j`P`J`a` `n`r`u`t`e`r`;`)`8`b`V`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"/`*`@` `}`;`)`7`j`D`P`a`(`6`v`W`Q`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"/`*`@` `}`;`5`k`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`y`C`D`a` `r`a`v` `;" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`0` `=` `7`s`R`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`y`A`a` `r`a`v` ` ` ` \")), " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNJk7(\"/`*`@` `}`;`3`k`E`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}