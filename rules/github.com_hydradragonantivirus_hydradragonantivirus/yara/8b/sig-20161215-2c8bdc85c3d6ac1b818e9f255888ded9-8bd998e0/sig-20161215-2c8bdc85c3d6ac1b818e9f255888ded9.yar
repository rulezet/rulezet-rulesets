rule sig_20161215_2c8bdc85c3d6ac1b818e9f255888ded9 {
  meta:
    description = "datamaliciousorder - file 20161215_2c8bdc85c3d6ac1b818e9f255888ded9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502d5bd6ca3a122b52522b5cdd90520410587d1505080e619696dda1a564a441"

  strings:
    $s1  = "function aIWb5(aDDw3) {eval(\"/*@cc_on var aKDb6 = new Date() @*/\");aKDb6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKDb6[\"ge" ascii
    $s2  = "function aIWb5(aDDw3) {eval(\"/*@cc_on var aKDb6 = new Date() @*/\");aKDb6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKDb6[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`1`+`1`=`6`f`T`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`c`E`X`a`=`8`h" ascii
    $s8  = "conds\"]()[\"toString\"](10) == \"20\") {var aUi9 = aDDw3[\"split\"](\"`\"); return aUi9[\"reverse\"]().join(\"\");} else return" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`2`n`J`a` `+` `7`d`C`H`a`=`8`c`E`X`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`n`U`a` `n`r`u`t`e`r`;`)`8`h`E`J`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`w`Z`C`a`;`)`2` `,`1`g`K`S`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`p`q`1`y`r`x`2`/`m`o`c`.`r`a`e`w`r`e`f`a`l`\\x22` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\"/`*`@` `}`;`)`2`k`P`a`(`9`l`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`d`K`Y`a` `r`a`v` `;" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIWb5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`n`U`a` `n`r`u`t`e`r`;`)`8`h`E`J`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}