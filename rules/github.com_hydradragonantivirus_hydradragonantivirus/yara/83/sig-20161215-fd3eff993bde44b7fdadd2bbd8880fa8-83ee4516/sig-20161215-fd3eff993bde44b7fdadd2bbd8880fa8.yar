rule sig_20161215_fd3eff993bde44b7fdadd2bbd8880fa8 {
  meta:
    description = "datamaliciousorder - file 20161215_fd3eff993bde44b7fdadd2bbd8880fa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76dd43ac1feac374352b001616d10fced7235e0a95505f9c4f7b3c7217cfacea"

  strings:
    $s1  = "function aICa4(aHYi1) {eval(\"/*@cc_on var aPa3 = new Date() @*/\");aPa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPa3[\"getUT" ascii
    $s2  = "function aICa4(aHYi1) {eval(\"/*@cc_on var aPa3 = new Date() @*/\");aPa3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPa3[\"getUT" ascii
    $s3  = "ds\"]()[\"toString\"](10) == \"20\") {var aTn9 = aHYi1[\"split\"](\"`\"); return aTn9[\"reverse\"]().join(\"\");} else return \"" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`c`g`o`m`v`a`k`4`t`/`n`c`.`k`r`o`w`t`a`\\x22` `+` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`8`h`C`X`a` `+` `2`v`V`a`=`5`w`T`Z`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\"/`*`@` `}`;`6`j`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`p`M`a`;`)`2` `,`8`a`K`Z`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`p`M`a`;`)`2` `,`8`a`K`Z`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`1`+`1`=`5`b`I`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`w`T`Z`a`=`7`m" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`r`Y`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\"/`*`@` `}`;`)`1`e`H`W`a`(`8`g`E`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`r`Y`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aICa4(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}