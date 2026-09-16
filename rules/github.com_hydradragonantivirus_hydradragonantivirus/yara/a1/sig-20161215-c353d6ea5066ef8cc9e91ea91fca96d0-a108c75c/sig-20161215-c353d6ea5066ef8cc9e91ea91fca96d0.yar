rule sig_20161215_c353d6ea5066ef8cc9e91ea91fca96d0 {
  meta:
    description = "datamaliciousorder - file 20161215_c353d6ea5066ef8cc9e91ea91fca96d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c3065b7a5194c13684dc84b2b41ff5624d4d0adfb6225d1f3c2db8444e6e7fe"

  strings:
    $s1  = "function aXVr4(aGGq5) {eval(\"/*@cc_on var aDj8 = new Date() @*/\");aDj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDj8[\"getUT" ascii
    $s2  = "function aXVr4(aGGq5) {eval(\"/*@cc_on var aDj8 = new Date() @*/\");aDj8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDj8[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"/`*`@` `}`;`4`l`Y`K`a` `n`r`u`t`e`r`;`}`;`)`9`f`I`M`a`(`]`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`b`H`a` `n`r`u`t`e`r`;`)`0`p`H`a`(" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"/`*`@` `}`;`0`m`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`c" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`1`+`1`=`3`w`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`b`H`a` `n`r`u`t`e`r`;`)`0`p`H`a`(" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`0` `=` `9`t`A`H`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`q`B`a` `r`a`v` `;`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"/`*`@` `}`;`5`q`G`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`q`B`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`1`+`1`=`3`w`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"/`*`@` `}`;`)`2`j`B`a`(`6`p`M`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXVr4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}