rule sig_20161215_0724375a6641cc22b351f457a4baf1bc {
  meta:
    description = "datamaliciousorder - file 20161215_0724375a6641cc22b351f457a4baf1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef76fff1e293c6142e39f9c682e241f932f3ef58d54ff359f82b620618f2853e"

  strings:
    $s1  = "function aIj3(aKg5) {eval(\"/*@cc_on var aZGr9 = new Date() @*/\");aZGr9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZGr9[\"getU" ascii
    $s2  = "function aIj3(aKg5) {eval(\"/*@cc_on var aZGr9 = new Date() @*/\");aZGr9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZGr9[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`1`+`1`=`9`n`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`x`m`v`n`y`j`/`.`m`o`c`.`b`s`0`5`2`\\x22` `+` `1`i`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`k`C`P`a`;`)`2` `,`5`q`P`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`n`B`a` `r`a`v` ` ` ` \")), 1" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`k`C`P`a`;`)`2` `,`5`q`P`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`3`n`F`F`a` `+` `0`z`Q`a`=`3`s`U`N`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`5`g`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`)`8`t`K`T`a`(`1`q`L`C`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"}`;`h`t`a`P`t`r`o`h`S`.`6`b`E`a` `n`r`u`t`e`r`;`)`1`m`N`A`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`7`r`U`W`a` `n`r`u`t`e`r`;`}`;`)`2`i`T`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`w`j`f`c`3`w`i`a`/`m`o`c`.`j`a`z`y`e`p`n`o`y`z`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIj3(\"/`*`@` `}`;`3`h`L`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}