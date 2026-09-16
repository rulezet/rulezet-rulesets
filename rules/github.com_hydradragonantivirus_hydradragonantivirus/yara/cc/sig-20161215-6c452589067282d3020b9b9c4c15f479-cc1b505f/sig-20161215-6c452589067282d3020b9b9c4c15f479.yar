rule sig_20161215_6c452589067282d3020b9b9c4c15f479 {
  meta:
    description = "datamaliciousorder - file 20161215_6c452589067282d3020b9b9c4c15f479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1ff46dc9750029895ab86fe9740a61a3d395182eef4e9c8518444b12dbe3bde"

  strings:
    $s1  = "function aUc2(aONj3) {eval(\"/*@cc_on var aPNr2 = new Date() @*/\");aPNr2[\"setUTCSeconds\"](\"0\", \"20\");if (aPNr2.getUTCMill" ascii
    $s2  = "function aUc2(aONj3) {eval(\"/*@cc_on var aPNr2 = new Date() @*/\");aPNr2[\"setUTCSeconds\"](\"0\", \"20\");if (aPNr2.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`1`+`1`=`6`m`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s6  = "().toString(10) == \"20\") {var aVo4 = aONj3[\"split\"](\"`\"); return aVo4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\"/`*`@` `}`;`)`8`c`D`A`a`(`8`p`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`r`M`a`;`)`2` `,`3`y`X`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`0`r`V`O`a` `+` `3`z`V`W`a`=`8`j`M`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`o`L`a` `n`r`u`t`e`r`;`)`1`z`X`a`(`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`r`M`a`;`)`2` `,`3`y`X`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`j`M`a`=`1`z`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUc2(\";`1`+`1`=`6`m`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}