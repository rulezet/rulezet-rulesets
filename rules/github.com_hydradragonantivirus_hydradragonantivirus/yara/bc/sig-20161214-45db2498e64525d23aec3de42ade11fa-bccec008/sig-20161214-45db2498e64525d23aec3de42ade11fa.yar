rule sig_20161214_45db2498e64525d23aec3de42ade11fa {
  meta:
    description = "datamaliciousorder - file 20161214_45db2498e64525d23aec3de42ade11fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c31350f838cf956ada994ffccd3d65c476c00fcd794145703139e2e73c38c37d"

  strings:
    $s1  = "function aXk2(aBn1) {eval(\"/*@cc_on var aAXu7 = new Date() @*/\");aAXu7[\"setUTCSeconds\"](\"0\", \"20\");if (aAXu7.getUTCMilli" ascii
    $s2  = "function aXk2(aBn1) {eval(\"/*@cc_on var aAXu7 = new Date() @*/\");aAXu7[\"setUTCSeconds\"](\"0\", \"20\");if (aAXu7.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`0`h`I`a` `n`r`u`t`e`r`;`}`;`)`1`f`J`a`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`1`+`1`=`5`j`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`)`1`m`R`Q`a`(`5`y`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`8`w`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`g`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`u`X`a`=`8`g`B`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`a`R`a` `r`a`v` ` ` ` \")), 1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`1`+`1`=`5`j`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`1`n`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `2`q`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`8`w`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`g`" ascii
    $s19 = ").toString(10) == \"20\") {var aIh0 = aBn1[\"split\"](\"`\"); return aIh0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXk2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}