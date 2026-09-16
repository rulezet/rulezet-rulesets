rule sig_20161214_38774b0c05bf2fe7e1da5ade67899325 {
  meta:
    description = "datamaliciousorder - file 20161214_38774b0c05bf2fe7e1da5ade67899325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b8e71b4b72b97ed7e77b6800dca2dd840fc04446dd4e751b496f714afcfa6c8"

  strings:
    $s1  = "function aBQx1(aZDw9) {eval(\"/*@cc_on var aAOw2 = new Date() @*/\");aAOw2[\"setUTCSeconds\"](\"0\", \"20\");if (aAOw2.getUTCMil" ascii
    $s2  = "function aBQx1(aZDw9) {eval(\"/*@cc_on var aAOw2 = new Date() @*/\");aAOw2[\"setUTCSeconds\"](\"0\", \"20\");if (aAOw2.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `3`b`M`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`y`X`a`;`)`2` `,`3`t`N`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"/`*`@` `}`;`9`w`D`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"/`*`@` `}`;`)`7`h`L`K`a`(`4`b`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"/`*`@` `}`;`8`w`Y`X`a` `n`r`u`t`e`r`;`}`;`)`2`b`T`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"}`;`h`t`a`P`t`r`o`h`S`.`0`s`X`R`a` `n`r`u`t`e`r`;`)`8`k`X`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`u`I`a` `r`a`v` ` ` ` \")), " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\"/`*`@` `}`;`9`w`D`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBQx1(\";`8`k`C`Q`a` `+` `4`x`Q`A`a`=`0`c`B`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}