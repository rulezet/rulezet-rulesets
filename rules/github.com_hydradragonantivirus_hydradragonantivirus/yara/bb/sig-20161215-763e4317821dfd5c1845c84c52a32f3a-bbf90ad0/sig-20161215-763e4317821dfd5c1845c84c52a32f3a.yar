rule sig_20161215_763e4317821dfd5c1845c84c52a32f3a {
  meta:
    description = "datamaliciousorder - file 20161215_763e4317821dfd5c1845c84c52a32f3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27d95e57f00c3bd361b656ff8cce52b6b4dcc6d7dcda55c22f7590890f55ece8"

  strings:
    $s1  = "function aHXu5(aVMs3) {eval(\"/*@cc_on var aDl9 = new Date() @*/\");aDl9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDl9[\"getUT" ascii
    $s2  = "function aHXu5(aVMs3) {eval(\"/*@cc_on var aDl9 = new Date() @*/\");aDl9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDl9[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "ds\"]()[\"toString\"](10) == \"20\") {var aWv6 = aVMs3[\"split\"](\"`\"); return aWv6[\"reverse\"]().join(\"\");} else return \"" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`b`Z`a` `r`a`v` ` ` ` \")), " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\"/`*`@` `}`;`2`w`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`e`m`n`n`6`o`t`/`g`r`o`.`r`e`d`o`u`c`\\x22` `+` `3" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`1`+`1`=`7`t`W`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `3`x`J" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\"/`*`@` `}`;`3`s`M`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHXu5(\";`1`+`1`=`7`t`W`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}