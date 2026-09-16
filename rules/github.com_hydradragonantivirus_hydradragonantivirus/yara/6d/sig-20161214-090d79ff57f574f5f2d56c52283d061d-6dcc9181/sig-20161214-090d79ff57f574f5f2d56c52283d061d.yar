rule sig_20161214_090d79ff57f574f5f2d56c52283d061d {
  meta:
    description = "datamaliciousorder - file 20161214_090d79ff57f574f5f2d56c52283d061d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a934f26e4d52ec3b041eeaf8c73ca7ffb0ef22a89f7e4925d111beaf7cebc016"

  strings:
    $s1  = "function aQLo2(aSAy3) {eval(\"/*@cc_on var aZHn2 = new Date() @*/\");aZHn2[\"setUTCSeconds\"](\"0\", \"20\");if (aZHn2.getUTCMil" ascii
    $s2  = "function aQLo2(aSAy3) {eval(\"/*@cc_on var aZHn2 = new Date() @*/\");aZHn2[\"setUTCSeconds\"](\"0\", \"20\");if (aZHn2.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"/`*`@` `}`;`3`y`A`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`b`D`O`a`;`)`2` `,`0`n`O`G`a`(" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`j`Q`K`a`=`6`i" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `4`x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`1`+`1`=`7`g`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"/`*`@` `}`;`8`w`P`a` `n`r`u`t`e`r`;`}`;`)`8`n`M`K`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"/`*`@` `}`;`)`1`j`E`O`a`(`4`o`K`C`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `4" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\"/`*`@` `}`;`)`1`j`E`O`a`(`4`o`K`C`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQLo2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}