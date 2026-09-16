rule sig_20161215_5c0f19909f7efe515b50670914f7359e {
  meta:
    description = "datamaliciousorder - file 20161215_5c0f19909f7efe515b50670914f7359e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6090e66ef7a3179aa1d13fb8b192c32ed962beec87bd3d7907915499667486b1"

  strings:
    $s1  = "function aMYy3(aHg4) {eval(\"/*@cc_on var aQXw1 = new Date() @*/\");aQXw1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQXw1[\"get" ascii
    $s2  = "function aMYy3(aHg4) {eval(\"/*@cc_on var aQXw1 = new Date() @*/\");aQXw1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQXw1[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`9`t`G`a` `+` `5`b`R`U`a`=`6`x`W`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`4`g`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`2`f`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`9`v`X`a` `n`r`u`t`e`r`;`}`;`)`8`o`S`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`r`R`a`;`)`2` `,`4`f`X`T`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`r`R`a`;`)`2` `,`4`f`X`T`a`(`]" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`d`O`R`a` `r`a`v` `;" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"}`;`h`t`a`P`t`r`o`h`S`.`7`o`L`N`a` `n`r`u`t`e`r`;`)`4`s`Y`O" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\"/`*`@` `}`;`)`3`q`Y`U`a`(`9`j`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMYy3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}