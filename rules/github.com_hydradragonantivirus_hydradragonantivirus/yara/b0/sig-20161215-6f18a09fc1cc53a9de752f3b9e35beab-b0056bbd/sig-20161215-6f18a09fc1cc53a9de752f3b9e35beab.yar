rule sig_20161215_6f18a09fc1cc53a9de752f3b9e35beab {
  meta:
    description = "datamaliciousorder - file 20161215_6f18a09fc1cc53a9de752f3b9e35beab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2426e86a30825c8eba85d55a0dfa2fc666bfbe25cc15335147e779dffccb81fe"

  strings:
    $s1  = "function aRWs9(aJk3) {eval(\"/*@cc_on var aESl5 = new Date() @*/\");aESl5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aESl5[\"get" ascii
    $s2  = "function aRWs9(aJk3) {eval(\"/*@cc_on var aESl5 = new Date() @*/\");aESl5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aESl5[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`1`+`1`=`4`g`S`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\"}`;`h`t`a`P`t`r`o`h`S`.`0`z`Q`Z`a` `n`r`u`t`e`r`;`)`2`r`K`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`n`P`a`=`2`r`K" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`c`o`v`k`o`y`s`5`2`f`/`m`o`c`.`e`e`l`y`d`n`a`c`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\"/`*`@` `}`;`3`k`J`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`1`+`1`=`4`g`S`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\"/`*`@` `}`;`9`b`X`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\"/`*`@` `}`;`6`z`O`I`a` `n`r`u`t`e`r`;`}`;`)`3`j`X`a`(`]`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`0`g`R`a` `+` `5`k`X`a`=`9`n`P`a` `r`a`v\")), 1);" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRWs9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}