rule sig_20161215_44a9d0195e1c05ef46bb8c87efa28cb2 {
  meta:
    description = "datamaliciousorder - file 20161215_44a9d0195e1c05ef46bb8c87efa28cb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "327ad105352b65991e0cfa44791ec0f45ee0b1e90c1835be275753251bde84c5"

  strings:
    $s1  = "function aFv9(aUr4) {eval(\"/*@cc_on var aRTj6 = new Date() @*/\");aRTj6[\"setUTCSeconds\"](\"0\", \"20\");if (aRTj6.getUTCMilli" ascii
    $s2  = "function aFv9(aUr4) {eval(\"/*@cc_on var aRTj6 = new Date() @*/\");aRTj6[\"setUTCSeconds\"](\"0\", \"20\");if (aRTj6.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`w`M`N`a` `r`a`v` ` ` ` \"))," ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `2`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`1`+`1`=`4`a`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`f`J`a`;`)`2` `,`7`n`U`K`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`f`J`a`;`)`2` `,`7`n`U`K`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`)`0`k`G`a`(`7`n`Y`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`1`+`1`=`4`a`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`)`0`k`G`a`(`7`n`Y`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`4`r`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\"/`*`@` `}`;`1`y`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`o`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFv9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}