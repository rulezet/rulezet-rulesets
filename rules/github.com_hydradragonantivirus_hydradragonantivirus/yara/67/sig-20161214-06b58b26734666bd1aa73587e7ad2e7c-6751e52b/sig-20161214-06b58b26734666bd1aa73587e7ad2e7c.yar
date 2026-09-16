rule sig_20161214_06b58b26734666bd1aa73587e7ad2e7c {
  meta:
    description = "datamaliciousorder - file 20161214_06b58b26734666bd1aa73587e7ad2e7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf7af8aa4c3065ee9b1fce6b24a6670e19094f1735d114a9d9e696de499f9be6"

  strings:
    $s1  = "function aPLh4(aOb2) {eval(\"/*@cc_on var aVx4 = new Date() @*/\");aVx4[\"setUTCSeconds\"](\"0\", \"20\");if (aVx4.getUTCMillise" ascii
    $s2  = "function aPLh4(aOb2) {eval(\"/*@cc_on var aVx4 = new Date() @*/\");aVx4[\"setUTCSeconds\"](\"0\", \"20\");if (aVx4.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`e`Y`a`;`)`2` `,`8`e`S`L`a`(`]" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\"/`*`@` `}`;`2`z`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`u" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\"/`*`@` `}`;`2`b`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`1`+`1`=`8`d`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`u`R`a`=`9`f`Z" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`1`+`1`=`8`d`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\"/`*`@` `}`;`3`o`T`N`a` `n`r`u`t`e`r`;`}`;`)`6`k`W`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPLh4(\"\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}