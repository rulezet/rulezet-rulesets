rule sig_20161214_4647cae1a82783426bd56fc235de1f60 {
  meta:
    description = "datamaliciousorder - file 20161214_4647cae1a82783426bd56fc235de1f60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0fcd7d2d0d64a2736677bf95db13752cd4fd429791df1b7f52a5f3bb4c74a7b"

  strings:
    $s1  = "function aQVy4(aNTz5) {eval(\"/*@cc_on var aHKm7 = new Date() @*/\");aHKm7[\"setUTCSeconds\"](\"0\", \"20\");if (aHKm7.getUTCMil" ascii
    $s2  = "function aQVy4(aNTz5) {eval(\"/*@cc_on var aHKm7 = new Date() @*/\");aHKm7[\"setUTCSeconds\"](\"0\", \"20\");if (aHKm7.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"/`*`@` `}`;`4`o`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`h`Y`D`a`;`)`2` `,`4`g`Y`S`a`(" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"}`;`h`t`a`P`t`r`o`h`S`.`8`w`C`a` `n`r`u`t`e`r`;`)`5`u`U`a`(" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"/`*`@` `}`;`5`z`T`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`1`+`1`=`9`h`U`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`n`H`Q`a`=`5`u" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"}`;`h`t`a`P`t`r`o`h`S`.`8`w`C`a` `n`r`u`t`e`r`;`)`5`u`U`a`(" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"/`*`@` `}`;`8`d`F`S`a` `n`r`u`t`e`r`;`}`;`)`2`u`J`X`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`0` `=` `5`i`V`E`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\"/`*`@` `}`;`)`6`m`W`a`(`1`t`U`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`\\x22`o`w`b`3`k`5`n`i`n`/`m`o`c`.`3`2`1`t`s`e`t`x`0`1`t" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVy4(\";`0`v`Y`A`a` `+` `5`t`Z`Q`a`=`9`n`H`Q`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}