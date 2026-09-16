rule sig_20161215_6f42b3117564fe52df38165d58f19e6f {
  meta:
    description = "datamaliciousorder - file 20161215_6f42b3117564fe52df38165d58f19e6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "587367a6e597024900bb800818a1404599ba254d76232d1561a554a0129642e4"

  strings:
    $s1  = "function aNPq2(aIUa2) {eval(\"/*@cc_on var aGj1 = new Date() @*/\");aGj1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGj1[\"getUT" ascii
    $s2  = "function aNPq2(aIUa2) {eval(\"/*@cc_on var aGj1 = new Date() @*/\");aGj1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGj1[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`2`a`U`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"}`;`h`t`a`P`t`r`o`h`S`.`9`n`N`T`a` `n`r`u`t`e`r`;`)`4`k`D`Y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`v`D`R`a`=`4`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`b`H`N`a` `r`a`v` `;" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`0` `=` `2`i`D`A`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`2`a`U`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`)`7`e`A`O`a`(`1`l`P`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `7`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`l`K`a`;`)`2` `,`3`g`F`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNPq2(\"/`*`@` `}`;`6`c`S`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}