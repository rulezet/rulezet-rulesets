rule sig_20161215_c50a71f2e0ae3fc107f7a631cc119375 {
  meta:
    description = "datamaliciousorder - file 20161215_c50a71f2e0ae3fc107f7a631cc119375.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14e3acfd4c0c89c1582cf56f25daf5dc59b53c1e94e9d4e19c9e49e83989a740"

  strings:
    $s1  = "function aKe9(aKd2) {eval(\"/*@cc_on var aWb6 = new Date() @*/\");aWb6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWb6[\"getUTCM" ascii
    $s2  = "function aKe9(aKd2) {eval(\"/*@cc_on var aWb6 = new Date() @*/\");aWb6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWb6[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`3`c`L`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`3`w`G`a` `n`r`u`t`e`r`;`}`;`)`2`x`A`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `0`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`v`P`a` `r`a`v` ` ` ` \")), 1" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`h`T`W`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`v`V`E`a`;`)`2` `,`8`o`X`R`a`(`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`)`4`r`E`V`a`(`6`f`O`I`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`)`4`r`E`V`a`(`6`f`O`I`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `0`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`v`V`E`a`;`)`2` `,`8`o`X`R`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `0`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKe9(\";`1`+`1`=`3`s`K`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}