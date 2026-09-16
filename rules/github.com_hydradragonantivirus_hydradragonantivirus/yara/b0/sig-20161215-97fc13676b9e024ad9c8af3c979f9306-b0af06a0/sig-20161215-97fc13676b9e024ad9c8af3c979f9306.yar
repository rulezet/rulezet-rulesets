rule sig_20161215_97fc13676b9e024ad9c8af3c979f9306 {
  meta:
    description = "datamaliciousorder - file 20161215_97fc13676b9e024ad9c8af3c979f9306.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ce40deb6cf2057b0ee45426a055a2f08443414b70e0f02c51d5cfe54c4bdf9d"

  strings:
    $s1  = "function aGz1(aJJn3) {eval(\"/*@cc_on var aCYf0 = new Date() @*/\");aCYf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCYf0[\"get" ascii
    $s2  = "function aGz1(aJJn3) {eval(\"/*@cc_on var aCYf0 = new Date() @*/\");aCYf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCYf0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`7`b`G`X`a` `n`r`u`t`e`r`;`}`;`)`8`j`Z`a`(`]`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`h`J`T`a`;`)`2` `,`5`r`H`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`3`n`J`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`h`J`T`a`;`)`2` `,`5`r`H`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`1`+`1`=`5`o`V`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`)`0`g`X`a`(`6`h`T`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`)`0`g`X`a`(`6`h`T`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`1`+`1`=`5`o`V`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\"/`*`@` `}`;`3`n`J`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGz1(\";`0` `=` `2`u`X`G`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}