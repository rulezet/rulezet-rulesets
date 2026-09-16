rule sig_20161214_f6f294cf0144bb637179a10ab6018655 {
  meta:
    description = "datamaliciousorder - file 20161214_f6f294cf0144bb637179a10ab6018655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc85ac36ef02892a11dd531a25b4058ceb3cad0c9f2756e2fa6c50394b27269"

  strings:
    $s1  = "function aTVw7(aDGh8) {eval(\"/*@cc_on var aPu3 = new Date() @*/\");aPu3[\"setUTCSeconds\"](\"0\", \"20\");if (aPu3.getUTCMillis" ascii
    $s2  = "function aTVw7(aDGh8) {eval(\"/*@cc_on var aPu3 = new Date() @*/\");aPu3[\"setUTCSeconds\"](\"0\", \"20\");if (aPu3.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`1`l`C`Y`a` `n`r`u`t`e`r`;`}`;`)`0`a`K`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`a`M`a`;`)`2` `,`5`o`M`E`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`8`h`G`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`)`6`d`G`T`a`(`2`w`I`J`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`)`6`d`G`T`a`(`2`w`I`J`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`x`P`a`=`6`x`M" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"/`*`@` `}`;`5`c`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`d" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`z`Q`a` `r`a`v` ` ` ` \")), " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTVw7(\"}`;`h`t`a`P`t`r`o`h`S`.`8`i`R`a` `n`r`u`t`e`r`;`)`6`x`M`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}