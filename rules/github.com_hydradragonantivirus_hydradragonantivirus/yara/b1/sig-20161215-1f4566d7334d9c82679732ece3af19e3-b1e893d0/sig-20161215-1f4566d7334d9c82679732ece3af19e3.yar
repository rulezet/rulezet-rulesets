rule sig_20161215_1f4566d7334d9c82679732ece3af19e3 {
  meta:
    description = "datamaliciousorder - file 20161215_1f4566d7334d9c82679732ece3af19e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3218107741da4303f3fbaa9f6d911879a48525967d497fa48b1646cd8749ad08"

  strings:
    $s1  = "function aEQa2(aSYp2) {eval(\"/*@cc_on var aQOu8 = new Date() @*/\");aQOu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQOu8[\"ge" ascii
    $s2  = "function aEQa2(aSYp2) {eval(\"/*@cc_on var aQOu8 = new Date() @*/\");aQOu8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQOu8[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`N`V`a` `n`r`u`t`e`r`;`)`7`c`T`L" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`z`T`a` `r`a`v` `;`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`p`C`a`;`)`2` `,`4`o`J`Q`a`(`]" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`1`p`a`y`d`/`s`e`.`r`a`c`i`f`a`\\x22` `+` `2`c`P`I" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`z`T`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`v`U`M`a`=`7`c" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`0`h`W`Q`a` `+` `5`r`R`W`a`=`9`v`U`M`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`1`+`1`=`7`q`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "conds\"]()[\"toString\"](10) == \"20\") {var aWPt4 = aSYp2[\"split\"](\"`\"); return aWPt4[\"reverse\"]().join(\"\");} else retu" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEQa2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`p`C`a`;`)`2` `,`4`o`J`Q`a`(`]" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}