rule sig_20161215_10a5e8e419ed83b75852dfb57491094f {
  meta:
    description = "datamaliciousorder - file 20161215_10a5e8e419ed83b75852dfb57491094f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9be1cccb4a6567bd3b9cdc95741822cfeeb93c2fe77a3df89b3048431cabee45"

  strings:
    $s1  = "function aZz3(aFk2) {eval(\"/*@cc_on var aMb4 = new Date() @*/\");aMb4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMb4[\"getUTCM" ascii
    $s2  = "function aZz3(aFk2) {eval(\"/*@cc_on var aMb4 = new Date() @*/\");aMb4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMb4[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`2`c`U`E`a` `n`r`u`t`e`r`;`}`;`)`4`y`S`X`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`2`c`U`E`a` `n`r`u`t`e`r`;`}`;`)`4`y`S`X`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"}`;`h`t`a`P`t`r`o`h`S`.`6`s`O`N`a` `n`r`u`t`e`r`;`)`5`a`T`Z`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` `" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`)`2`s`B`Z`a`(`1`j`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`2`k`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`0` `=` `1`g`Y`J`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`n`D`a`;`)`2` `,`4`x`E`A`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"/`*`@` `}`;`2`k`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`h`4`u`t`k`h`5`/`o`r`.`n`i`z`a`g`a`m`q`.`e`n`u`a`c`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` `" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZz3(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}