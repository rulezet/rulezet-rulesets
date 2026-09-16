rule sig_20161215_f8061fce2c844fcb6039f3046253e5a4 {
  meta:
    description = "datamaliciousorder - file 20161215_f8061fce2c844fcb6039f3046253e5a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c20d04891740d8e86355090196b30c103f1fd54d8ee8e63bcfe3145edb28f815"

  strings:
    $s1  = "function aWEd8(aAw1) {eval(\"/*@cc_on var aLy4 = new Date() @*/\");aLy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLy4[\"getUTC" ascii
    $s2  = "function aWEd8(aAw1) {eval(\"/*@cc_on var aLy4 = new Date() @*/\");aLy4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLy4[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`k`D`a`;`)`2` `,`8`i`G`R`a`(`]" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`1`q`P`N`a` `n`r`u`t`e`r`;`}`;`)`4`c`M`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`)`7`m`U`W`a`(`0`h`Z`G`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`u`D`a`=`7`u`L" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`1`w`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`u`D`a`=`7`u`L" ascii
    $s13 = "s\"]()[\"toString\"](10) == \"20\") {var aNPq1 = aAw1[\"split\"](\"`\"); return aNPq1[\"reverse\"]().join(\"\");} else return \"" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`3`g`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`m" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`1`+`1`=`7`z`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `0" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWEd8(\"/`*`@` `}`;`)`7`m`U`W`a`(`0`h`Z`G`a` `n`r`u`t`e`r`;`)`(`e`s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}