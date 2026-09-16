rule sig_20161214_fcb92944d5951e68e6ec5edaea55fafb {
  meta:
    description = "datamaliciousorder - file 20161214_fcb92944d5951e68e6ec5edaea55fafb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3479152300edb8687e33e89a12934bf4e121a2c719c98347ade2d5fbac2589ec"

  strings:
    $s1  = "function aKk7(aJl5) {eval(\"/*@cc_on var aNa6 = new Date() @*/\");aNa6[\"setUTCSeconds\"](\"0\", \"20\");if (aNa6.getUTCMillisec" ascii
    $s2  = "function aKk7(aJl5) {eval(\"/*@cc_on var aNa6 = new Date() @*/\");aNa6[\"setUTCSeconds\"](\"0\", \"20\");if (aNa6.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`k`J`I`a`=`4`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `1`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"/`*`@` `}`;`0`v`Q`a` `n`r`u`t`e`r`;`}`;`)`5`i`M`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`i`I`a` `r`a`v` ` ` ` \")), 1" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`1`+`1`=`1`g`C`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"/`*`@` `}`;`3`v`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`x`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`4`d`B`W`a` `+` `3`s`K`C`a`=`1`k`J`I`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"/`*`@` `}`;`3`v`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`x`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"/`*`@` `}`;`5`l`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\"/`*`@` `}`;`)`2`e`M`a`(`5`q`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`1`+`1`=`1`g`C`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKk7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}