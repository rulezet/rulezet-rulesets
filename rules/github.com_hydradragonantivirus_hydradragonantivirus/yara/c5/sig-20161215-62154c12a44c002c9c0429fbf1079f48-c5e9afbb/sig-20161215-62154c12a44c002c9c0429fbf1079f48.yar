rule sig_20161215_62154c12a44c002c9c0429fbf1079f48 {
  meta:
    description = "datamaliciousorder - file 20161215_62154c12a44c002c9c0429fbf1079f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09b3c441488a7f44eab2de1873eead71c36d7345bd096e23a8834aba06bb27b6"

  strings:
    $s1  = "function aZy9(aXh5) {eval(\"/*@cc_on var aEy0 = new Date() @*/\");aEy0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEy0[\"getUTCM" ascii
    $s2  = "function aZy9(aXh5) {eval(\"/*@cc_on var aEy0 = new Date() @*/\");aEy0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEy0[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`0` `=` `2`u`D`C`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`d`Z`Y`a`=`1`s`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`2`k`M`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`)`8`j`X`a`(`5`i`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`l`N`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`2`k`M`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`u`C`a` `r`a`v` ` ` ` \")), 1" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\"/`*`@` `}`;`5`h`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZy9(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}