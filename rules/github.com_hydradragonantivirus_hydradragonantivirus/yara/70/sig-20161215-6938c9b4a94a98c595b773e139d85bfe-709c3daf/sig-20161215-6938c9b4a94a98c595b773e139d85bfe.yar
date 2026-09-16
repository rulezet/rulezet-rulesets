rule sig_20161215_6938c9b4a94a98c595b773e139d85bfe {
  meta:
    description = "datamaliciousorder - file 20161215_6938c9b4a94a98c595b773e139d85bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63bac45774a74413b30f736fef7e40e54b4640436948f286a8b621d1a3613299"

  strings:
    $s1  = "function aFg1(aLc0) {eval(\"/*@cc_on var aBDf2 = new Date() @*/\");aBDf2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBDf2[\"getU" ascii
    $s2  = "function aFg1(aLc0) {eval(\"/*@cc_on var aBDf2 = new Date() @*/\");aBDf2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBDf2[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s4  = "nds\"]()[\"toString\"](10) == \"20\") {var aFZg8 = aLc0[\"split\"](\"`\"); return aFZg8[\"reverse\"]().join(\"\");} else return " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\"/`*`@` `}`;`8`g`Z`F`a` `n`r`u`t`e`r`;`}`;`)`5`q`E`a`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`0` `=` `3`f`R`E`a` `r`a`v\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `6`q`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `6`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`q`V`a`;`)`2` `,`7`u`J`D`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\"/`*`@` `}`;`0`c`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\"}`;`h`t`a`P`t`r`o`h`S`.`7`g`U`a` `n`r`u`t`e`r`;`)`7`v`R`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `6`q`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`r`W`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFg1(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `6`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}