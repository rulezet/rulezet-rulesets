rule sig_20161215_381a70f2cba13b67ca3b42b332c82810 {
  meta:
    description = "datamaliciousorder - file 20161215_381a70f2cba13b67ca3b42b332c82810.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd24dd0dff74fcd3f908122849d74e99a79e9ed0dddb8f494ae8313c2e38bedc"

  strings:
    $s1  = "function aFd8(aDRo1) {eval(\"/*@cc_on var aIHf9 = new Date() @*/\");aIHf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIHf9[\"get" ascii
    $s2  = "function aFd8(aDRo1) {eval(\"/*@cc_on var aIHf9 = new Date() @*/\");aIHf9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIHf9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `4`u`N`R`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`m`D`a`;`)`2` `,`8`l`E`V`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `4`u`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`5`z`D`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`5`z`D`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`t`Q`a`=`8`m`O`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`e`O`E`a` `r`a`v` ` ` ` \"))," ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`9`j`E`U`a` `n`r`u`t`e`r`;`}`;`)`3`u`U`a`(`]`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\"/`*`@` `}`;`)`4`t`R`a`(`4`r`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}