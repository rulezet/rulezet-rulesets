rule sig_20161215_f4d561a7db9feef0e42530a05aba7c53 {
  meta:
    description = "datamaliciousorder - file 20161215_f4d561a7db9feef0e42530a05aba7c53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a338a63274afdf88aabed927f64c7a37512be31e9fd7ab7bc12fb9e1de86c10e"

  strings:
    $s1  = "function aIPn5(aDe6) {eval(\"/*@cc_on var aJt5 = new Date() @*/\");aJt5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJt5[\"getUTC" ascii
    $s2  = "function aIPn5(aDe6) {eval(\"/*@cc_on var aJt5 = new Date() @*/\");aJt5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJt5[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`z`S`Q`a`=`9`s" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`z`S`Q`a`=`9`s" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\"/`*`@` `}`;`6`e`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `3`n" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`e`W`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\"/`*`@` `}`;`)`4`g`N`a`(`5`u`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\"/`*`@` `}`;`4`v`G`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`l`5`j`3`d`/`a`c`.`e`l`l`i`v`s`l`l`i`b`-`g`n`a`h`n" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\"/`*`@` `}`;`7`e`G`I`a` `n`r`u`t`e`r`;`}`;`)`7`l`D`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIPn5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`e`W`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}