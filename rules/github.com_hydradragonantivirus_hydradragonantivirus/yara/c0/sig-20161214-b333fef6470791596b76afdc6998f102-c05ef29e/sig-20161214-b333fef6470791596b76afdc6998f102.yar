rule sig_20161214_b333fef6470791596b76afdc6998f102 {
  meta:
    description = "datamaliciousorder - file 20161214_b333fef6470791596b76afdc6998f102.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "156977175272170708153f4a963645d246e3bb9b4a1b82bccfd198e999c4fa1d"

  strings:
    $s1  = "function aXp0(aGXp7) {eval(\"/*@cc_on var aGHz1 = new Date() @*/\");aGHz1[\"setUTCSeconds\"](\"0\", \"20\");if (aGHz1.getUTCMill" ascii
    $s2  = "function aXp0(aGXp7) {eval(\"/*@cc_on var aGHz1 = new Date() @*/\");aGHz1[\"setUTCSeconds\"](\"0\", \"20\");if (aGHz1.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`o`I`a`=`2`t`L`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`l`O`a` `n`r`u`t`e`r`;`)`2`t`L`a`(`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`j`B`R`a`;`)`2` `,`9`l`J`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`7`p`X`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`l`O`a` `n`r`u`t`e`r`;`)`2`t`L`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`7`p`X`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`0` `=` `9`l`H`C`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\"/`*`@` `}`;`8`r`M`a` `n`r`u`t`e`r`;`}`;`)`3`p`T`a`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXp0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}