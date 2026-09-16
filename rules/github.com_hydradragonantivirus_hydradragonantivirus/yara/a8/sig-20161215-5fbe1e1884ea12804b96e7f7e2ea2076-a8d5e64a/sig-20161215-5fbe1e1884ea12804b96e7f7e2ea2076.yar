rule sig_20161215_5fbe1e1884ea12804b96e7f7e2ea2076 {
  meta:
    description = "datamaliciousorder - file 20161215_5fbe1e1884ea12804b96e7f7e2ea2076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de982511c97096baf81ffea50eca4c1fa915ba529979fecb74e6dca55d95a192"

  strings:
    $s1  = "function aCt9(aTQe6) {eval(\"/*@cc_on var aDVc7 = new Date() @*/\");aDVc7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDVc7[\"get" ascii
    $s2  = "function aCt9(aTQe6) {eval(\"/*@cc_on var aDVc7 = new Date() @*/\");aDVc7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aDVc7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`1`+`1`=`9`b`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`0` `=` `5`w`F`V`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s9  = "onds\"]()[\"toString\"](10) == \"20\") {var aSNn1 = aTQe6[\"split\"](\"`\"); return aSNn1[\"reverse\"]().join(\"\");} else retur" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\"/`*`@` `}`;`6`e`Q`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\"}`;`h`t`a`P`t`r`o`h`S`.`9`n`C`a` `n`r`u`t`e`r`;`)`4`i`K`a`(`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\"/`*`@` `}`;`)`5`m`B`a`(`6`e`L`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`h`H`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`f`V`R`a`;`)`2` `,`6`q`O`Z`a`(`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCt9(\";`1`+`1`=`9`b`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}