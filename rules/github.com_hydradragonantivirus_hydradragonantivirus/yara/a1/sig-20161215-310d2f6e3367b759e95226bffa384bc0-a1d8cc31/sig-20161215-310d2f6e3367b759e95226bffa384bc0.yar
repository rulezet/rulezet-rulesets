rule sig_20161215_310d2f6e3367b759e95226bffa384bc0 {
  meta:
    description = "datamaliciousorder - file 20161215_310d2f6e3367b759e95226bffa384bc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e134acabb0f8b553d16dd58d91966684e47c04fd735a68c18f0d83f58942921e"

  strings:
    $s1  = "function aORp8(aSb9) {eval(\"/*@cc_on var aZAk5 = new Date() @*/\");aZAk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZAk5[\"get" ascii
    $s2  = "function aORp8(aSb9) {eval(\"/*@cc_on var aZAk5 = new Date() @*/\");aZAk5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZAk5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`5`h`Q`a` `n`r`u`t`e`r`;`}`;`)`2`g`T`a`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"}`;`h`t`a`P`t`r`o`h`S`.`0`r`F`a` `n`r`u`t`e`r`;`)`7`i`Y`O`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`0` `=` `1`e`L`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`6`q`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`p`T`a`;`)`2` `,`8`i`G`F`a`(`]" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`)`\\x22`v`b`q`h`p`x`/`p`j`.`e`t`i`l`i`t`g`\\x22` `+` `9`r" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`1`+`1`=`4`n`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`)`9`x`F`C`a`(`6`f`D`L`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`j`B`a`=`7`i`Y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\"/`*`@` `}`;`6`q`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aORp8(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+" ascii
    $s20 = "onds\"]()[\"toString\"](10) == \"20\") {var aQh5 = aSb9[\"split\"](\"`\"); return aQh5[\"reverse\"]().join(\"\");} else return " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}