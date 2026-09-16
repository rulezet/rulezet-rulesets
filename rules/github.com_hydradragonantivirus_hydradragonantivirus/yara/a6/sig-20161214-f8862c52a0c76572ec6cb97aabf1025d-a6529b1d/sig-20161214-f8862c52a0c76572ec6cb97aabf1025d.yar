rule sig_20161214_f8862c52a0c76572ec6cb97aabf1025d {
  meta:
    description = "datamaliciousorder - file 20161214_f8862c52a0c76572ec6cb97aabf1025d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ad8c5b4311274a3d6aefa17b248a2528d46818acac0b50522d9f8f8f42909c3"

  strings:
    $s1  = "function aOHt6(aIBr3) {eval(\"/*@cc_on var aRAi0 = new Date() @*/\");aRAi0[\"setUTCSeconds\"](\"0\", \"20\");if (aRAi0.getUTCMil" ascii
    $s2  = "function aOHt6(aIBr3) {eval(\"/*@cc_on var aRAi0 = new Date() @*/\");aRAi0[\"setUTCSeconds\"](\"0\", \"20\");if (aRAi0.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`7`b`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`i" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`g`Q`M`a`;`)`2` `,`7`c`T`a`(`]" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "s().toString(10) == \"20\") {var aBQg4 = aIBr3[\"split\"](\"`\"); return aBQg4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`4`g`Q`B`a` `n`r`u`t`e`r`;`}`;`)`4`x`T`W`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`g`Q`M`a`;`)`2` `,`7`c`T`a`(`]" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`3`r`B`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`)`0`g`T`H`a`(`8`c`H`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOHt6(\"/`*`@` `}`;`3`r`B`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}