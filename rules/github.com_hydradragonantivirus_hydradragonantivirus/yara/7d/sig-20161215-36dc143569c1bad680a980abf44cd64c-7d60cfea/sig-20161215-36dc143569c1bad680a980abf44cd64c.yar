rule sig_20161215_36dc143569c1bad680a980abf44cd64c {
  meta:
    description = "datamaliciousorder - file 20161215_36dc143569c1bad680a980abf44cd64c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6345fd84a1e7f5f5842e095cffa288adf6ea53f7cab1941e7a31c89db0a114"

  strings:
    $s1  = "function aWWz7(aXi8) {eval(\"/*@cc_on var aAEz4 = new Date() @*/\");aAEz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAEz4[\"get" ascii
    $s2  = "function aWWz7(aXi8) {eval(\"/*@cc_on var aAEz4 = new Date() @*/\");aAEz4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aAEz4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"/`*`@` `}`;`8`i`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`u`R`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`u`R`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`n`F`a`;`)`2` `,`5`j`W`Z`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`0` `=` `3`l`I`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"/`*`@` `}`;`7`q`S`a` `n`r`u`t`e`r`;`}`;`)`6`x`W`a`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"/`*`@` `}`;`)`5`s`T`N`a`(`6`r`X`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`1`+`1`=`5`p`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`q`D`I`a`=`9`h" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`l`F`T`a` `r`a`v` ` ` ` \"))" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`3`i`A`a` `+` `5`j`H`F`a`=`5`q`D`I`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`)`\\x22`f`a`w`b`p`j`0`/`r`k`.`o`c`.`t`s`u`r`t`g`i`b`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\"}`;`h`t`a`P`t`r`o`h`S`.`1`q`A`a` `n`r`u`t`e`r`;`)`9`h`C`P`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWWz7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`q`D`I`a`=`9`h" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}