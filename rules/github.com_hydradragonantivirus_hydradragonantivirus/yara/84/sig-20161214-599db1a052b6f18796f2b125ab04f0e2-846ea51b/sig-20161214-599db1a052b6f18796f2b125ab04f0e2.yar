rule sig_20161214_599db1a052b6f18796f2b125ab04f0e2 {
  meta:
    description = "datamaliciousorder - file 20161214_599db1a052b6f18796f2b125ab04f0e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39cdc40c3174c4cd412eee65ca55e533ec16329408955bc6b2c35cd73e2cd0a"

  strings:
    $s1  = "function aPIk7(aWa1) {eval(\"/*@cc_on var aYx0 = new Date() @*/\");aYx0[\"setUTCSeconds\"](\"0\", \"20\");if (aYx0.getUTCMillise" ascii
    $s2  = "function aPIk7(aWa1) {eval(\"/*@cc_on var aYx0 = new Date() @*/\");aYx0[\"setUTCSeconds\"](\"0\", \"20\");if (aYx0.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"}`;`h`t`a`P`t`r`o`h`S`.`5`r`Y`B`a` `n`r`u`t`e`r`;`)`0`g`T`U" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"/`*`@` `}`;`1`s`F`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"/`*`@` `}`;`5`e`H`F`a` `n`r`u`t`e`r`;`}`;`)`8`i`H`P`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"/`*`@` `}`;`5`e`H`F`a` `n`r`u`t`e`r`;`}`;`)`8`i`H`P`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`v`L`N`a`=`0`g" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`1`+`1`=`7`j`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"/`*`@` `}`;`1`a`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`u`X`D`a`;`)`2` `,`2`e`E`a`(`]" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`1`+`1`=`7`j`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `8`r`F`X" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPIk7(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}