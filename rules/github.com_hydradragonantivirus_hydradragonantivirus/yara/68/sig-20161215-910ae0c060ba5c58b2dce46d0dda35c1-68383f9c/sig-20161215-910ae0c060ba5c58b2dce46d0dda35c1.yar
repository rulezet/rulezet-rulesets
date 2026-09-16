rule sig_20161215_910ae0c060ba5c58b2dce46d0dda35c1 {
  meta:
    description = "datamaliciousorder - file 20161215_910ae0c060ba5c58b2dce46d0dda35c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2655b43de26d4bfe6dc4d9c7a9d6617c8d70c9b4ac61b0b87d908b40b22f80d5"

  strings:
    $s1  = "function aMb3(aVg0) {eval(\"/*@cc_on var aKt4 = new Date() @*/\");aKt4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKt4[\"getUTCM" ascii
    $s2  = "function aMb3(aVg0) {eval(\"/*@cc_on var aKt4 = new Date() @*/\");aKt4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aKt4[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `7`p`V`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`g`K`a` `r`a`v` ` ` ` \")), 1" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`t`Y`H`a`=`8`x`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`0` `=` `5`b`R`L`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`1`+`1`=`2`u`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`x`X`F`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\"/`*`@` `}`;`0`g`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`a`Z`E`a`;`)`2` `,`7`g`R`W`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMb3(\"/`*`@` `}`;`0`o`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}