rule sig_20161215_f8c28e3fdb7fa7659e682922138bd0c0 {
  meta:
    description = "datamaliciousorder - file 20161215_f8c28e3fdb7fa7659e682922138bd0c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "311317258bc1afc0159eb90530182ee5b85e4d949adabf7400f04dadbfacaec9"

  strings:
    $s1  = "function aWWb5(aPAj7) {eval(\"/*@cc_on var aCt5 = new Date() @*/\");aCt5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCt5[\"getUT" ascii
    $s2  = "function aWWb5(aPAj7) {eval(\"/*@cc_on var aCt5 = new Date() @*/\");aCt5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCt5[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"}`;`h`t`a`P`t`r`o`h`S`.`4`g`K`a` `n`r`u`t`e`r`;`)`2`j`P`Z`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`)`3`n`V`a`(`3`e`Q`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`7`q`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`y" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`7`q`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`7`j`A`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`0` `=` `0`a`S`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`v`Q`K`a`=`2`j" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`x`E`B`a`;`)`2` `,`2`c`F`a`(`]" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\"/`*`@` `}`;`)`3`n`V`a`(`3`e`Q`F`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`1`+`1`=`5`u`F`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`\\x22`b`u`r`v`2`m`7`/`v`t`.`e`t`a`g`d`o`o`g`\\x22` `+` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWb5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`u`X`a` `r`a`v` ` ` ` \")), " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}