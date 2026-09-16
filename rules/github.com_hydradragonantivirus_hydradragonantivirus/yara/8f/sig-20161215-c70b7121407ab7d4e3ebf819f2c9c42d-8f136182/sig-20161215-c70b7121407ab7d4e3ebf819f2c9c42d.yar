rule sig_20161215_c70b7121407ab7d4e3ebf819f2c9c42d {
  meta:
    description = "datamaliciousorder - file 20161215_c70b7121407ab7d4e3ebf819f2c9c42d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9334cde8ffc0eee8374ecfb23627216388c97375f0345a0f62384e4c8d214d4"

  strings:
    $s1  = "function aHu9(aJi1) {eval(\"/*@cc_on var aRNm6 = new Date() @*/\");aRNm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRNm6[\"getU" ascii
    $s2  = "function aHu9(aJi1) {eval(\"/*@cc_on var aRNm6 = new Date() @*/\");aRNm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRNm6[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`1`+`1`=`9`z`J`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"/`*`@` `}`;`1`i`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`c`G`X`a`;`)`2` `,`2`y`Z`U`a`(`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`p`W`Q`a` `n`r`u`t`e`r`;`)`0`p`Q`S`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"/`*`@` `}`;`)`0`u`O`a`(`6`l`G`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `2`g`N`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHu9(\"/`*`@` `}`;`2`q`J`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}