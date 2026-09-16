rule sig_20161215_de6402e74906f9ca2e4b31ceae0e909a {
  meta:
    description = "datamaliciousorder - file 20161215_de6402e74906f9ca2e4b31ceae0e909a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9156da4aa8b1557645f85ea69d4d916fdaada83fb3ab500c51291bb160451a7"

  strings:
    $s1  = "function aPd6(aSWb6) {eval(\"/*@cc_on var aJPg3 = new Date() @*/\");aJPg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJPg3[\"get" ascii
    $s2  = "function aPd6(aSWb6) {eval(\"/*@cc_on var aJPg3 = new Date() @*/\");aJPg3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJPg3[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `3`x`J`a`(`h`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`0` `=` `9`g`N`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`a`F`a`=`7`r`T`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\"/`*`@` `}`;`8`p`D`a` `n`r`u`t`e`r`;`}`;`)`9`r`D`N`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`a`I`a`;`)`2` `,`8`e`X`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `3`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "onds\"]()[\"toString\"](10) == \"20\") {var aDp8 = aSWb6[\"split\"](\"`\"); return aDp8[\"reverse\"]().join(\"\");} else return " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`z`l`l`b`o`6`/`m`o`c`.`l`l`e`w`o`l`l`o`h`t`a`k`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\"}`;`h`t`a`P`t`r`o`h`S`.`8`k`J`a` `n`r`u`t`e`r`;`)`7`r`T`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`a`F`a`=`7`r`T`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPd6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}