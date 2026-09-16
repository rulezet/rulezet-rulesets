rule sig_20161214_0c2c975b1f0e61378861a733bfc9bd65 {
  meta:
    description = "datamaliciousorder - file 20161214_0c2c975b1f0e61378861a733bfc9bd65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ce58aeb0303060d0039291bad90ba84ea0326f30ce46ac34e2796129ed7491"

  strings:
    $s1  = "function aQc3(aTLp3) {eval(\"/*@cc_on var aGHl6 = new Date() @*/\");aGHl6[\"setUTCSeconds\"](\"0\", \"20\");if (aGHl6.getUTCMill" ascii
    $s2  = "function aQc3(aTLp3) {eval(\"/*@cc_on var aGHl6 = new Date() @*/\");aGHl6[\"setUTCSeconds\"](\"0\", \"20\");if (aGHl6.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\"}`;`h`t`a`P`t`r`o`h`S`.`2`m`X`a` `n`r`u`t`e`r`;`)`0`i`W`M`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\"/`*`@` `}`;`6`l`F`P`a` `n`r`u`t`e`r`;`}`;`)`7`n`V`P`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`0` `=` `8`y`O`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\"/`*`@` `}`;`3`p`L`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`1`+`1`=`7`a`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s13 = "().toString(10) == \"20\") {var aPFl6 = aTLp3[\"split\"](\"`\"); return aPFl6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\"/`*`@` `}`;`)`3`k`N`a`(`4`y`X`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\"}`;`h`t`a`P`t`r`o`h`S`.`2`m`X`a` `n`r`u`t`e`r`;`)`0`i`W`M`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQc3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}