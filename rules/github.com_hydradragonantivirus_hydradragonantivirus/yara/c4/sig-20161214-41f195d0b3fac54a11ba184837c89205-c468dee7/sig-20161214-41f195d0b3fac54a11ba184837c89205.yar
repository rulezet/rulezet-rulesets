rule sig_20161214_41f195d0b3fac54a11ba184837c89205 {
  meta:
    description = "datamaliciousorder - file 20161214_41f195d0b3fac54a11ba184837c89205.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9fd9fd891588b4d1c2a35bf519765bc77e99c77461de073f3cd3f77288626bd"

  strings:
    $s1  = "function aLp0(aGVh4) {eval(\"/*@cc_on var aCt0 = new Date() @*/\");aCt0[\"setUTCSeconds\"](\"0\", \"20\");if (aCt0.getUTCMillise" ascii
    $s2  = "function aLp0(aGVh4) {eval(\"/*@cc_on var aCt0 = new Date() @*/\");aCt0[\"setUTCSeconds\"](\"0\", \"20\");if (aCt0.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`b`G`H`a`=`4`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`2`f`I`a` `n`r`u`t`e`r`;`}`;`)`9`v`L`T`a`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`e`G`I`a`;`)`2` `,`2`p`L`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`v`C`a` `r`a`v` ` ` ` \")), 1" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`e`G`I`a`;`)`2` `,`2`p`L`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`b`G`H`a`=`4`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLp0(\"/`*`@` `}`;`)`5`u`R`a`(`6`s`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}