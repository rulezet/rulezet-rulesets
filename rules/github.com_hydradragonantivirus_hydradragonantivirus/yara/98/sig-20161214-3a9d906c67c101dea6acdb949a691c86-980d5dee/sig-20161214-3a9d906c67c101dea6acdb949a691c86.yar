rule sig_20161214_3a9d906c67c101dea6acdb949a691c86 {
  meta:
    description = "datamaliciousorder - file 20161214_3a9d906c67c101dea6acdb949a691c86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c22c4416da08a6564956008e364cb3d9fe1083690a7c1da60ebf1678a858a418"

  strings:
    $s1  = "function aBl3(aDHj1) {eval(\"/*@cc_on var aRAy8 = new Date() @*/\");aRAy8[\"setUTCSeconds\"](\"0\", \"20\");if (aRAy8.getUTCMill" ascii
    $s2  = "function aBl3(aDHj1) {eval(\"/*@cc_on var aRAy8 = new Date() @*/\");aRAy8[\"setUTCSeconds\"](\"0\", \"20\");if (aRAy8.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`)`9`h`D`X`a`(`6`a`V`E`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`5`l`V`H`a` `+` `6`y`S`R`a`=`3`h`L`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`1`j`H`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`1`y`W`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`p`W`a`;`)`2` `,`3`k`H`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`1`+`1`=`7`c`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `0`y`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"}`;`h`t`a`P`t`r`o`h`S`.`6`f`V`A`a` `n`r`u`t`e`r`;`)`9`e`S`S`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`0`g`G`a` `n`r`u`t`e`r`;`}`;`)`3`n`H`M`a`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBl3(\"/`*`@` `}`;`1`y`W`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}