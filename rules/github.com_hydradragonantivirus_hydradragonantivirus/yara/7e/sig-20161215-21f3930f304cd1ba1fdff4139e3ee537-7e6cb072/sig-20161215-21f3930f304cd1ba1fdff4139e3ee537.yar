rule sig_20161215_21f3930f304cd1ba1fdff4139e3ee537 {
  meta:
    description = "datamaliciousorder - file 20161215_21f3930f304cd1ba1fdff4139e3ee537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a9cf954854e9385a7d13fdc0e74713aa76a6c91bd415ea75eedc8819cc31161"

  strings:
    $s1  = "function aEq6(aPUf0) {eval(\"/*@cc_on var aCd8 = new Date() @*/\");aCd8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCd8[\"getUTC" ascii
    $s2  = "function aEq6(aPUf0) {eval(\"/*@cc_on var aCd8 = new Date() @*/\");aCd8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aCd8[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`0` `=` `8`g`W`L`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`s`L`a`=`0`r`S`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\"/`*`@` `}`;`)`9`m`B`X`a`(`2`c`L`T`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\"/`*`@` `}`;`3`c`E`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\"/`*`@` `}`;`0`f`U`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`h`U`D`a` `n`r`u`t`e`r`;`)`0`r`S`a`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\"}`;`h`t`a`P`t`r`o`h`S`.`0`h`U`D`a` `n`r`u`t`e`r`;`)`0`r`S`a`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`1`+`1`=`7`v`G`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEq6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`s`L`a`=`0`r`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}