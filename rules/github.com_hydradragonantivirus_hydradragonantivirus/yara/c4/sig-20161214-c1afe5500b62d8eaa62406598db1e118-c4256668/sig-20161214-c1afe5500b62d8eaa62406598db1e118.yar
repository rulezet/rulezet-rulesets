rule sig_20161214_c1afe5500b62d8eaa62406598db1e118 {
  meta:
    description = "datamaliciousorder - file 20161214_c1afe5500b62d8eaa62406598db1e118.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f340255c695bd38b88717f72b699fa5a2f3fe6363ba6547eba6cc788a13b9c8"

  strings:
    $s1  = "function aSq0(aTc6) {eval(\"/*@cc_on var aKa5 = new Date() @*/\");aKa5[\"setUTCSeconds\"](\"0\", \"20\");if (aKa5.getUTCMillisec" ascii
    $s2  = "function aSq0(aTc6) {eval(\"/*@cc_on var aKa5 = new Date() @*/\");aKa5[\"setUTCSeconds\"](\"0\", \"20\");if (aKa5.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`y`G`P`a` `r`a`v` ` ` ` \"))," ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`3`o`J`W`a` `n`r`u`t`e`r`;`}`;`)`0`b`L`C`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`5`r`G`a` `+` `3`r`K`a`=`8`l`A`W`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`3`o`J`W`a` `n`r`u`t`e`r`;`}`;`)`0`b`L`C`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`0` `=` `0`b`P`V`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`6`c`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`h`V`J`a`;`)`2` `,`6`l`Q`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"}`;`h`t`a`P`t`r`o`h`S`.`7`a`H`O`a` `n`r`u`t`e`r`;`)`2`k`P`P`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`2`u`W`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\"/`*`@` `}`;`)`0`n`C`N`a`(`0`a`V`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `6`j`G`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSq0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}