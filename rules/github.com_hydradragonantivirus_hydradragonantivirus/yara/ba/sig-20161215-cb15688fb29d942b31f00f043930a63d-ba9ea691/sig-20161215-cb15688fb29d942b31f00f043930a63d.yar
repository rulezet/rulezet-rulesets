rule sig_20161215_cb15688fb29d942b31f00f043930a63d {
  meta:
    description = "datamaliciousorder - file 20161215_cb15688fb29d942b31f00f043930a63d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a469027461f4be6c43e9ac5c506c1a751baf5c43cd2bd226232d1fc5e62b93cd"

  strings:
    $s1  = "function aSe4(aODz8) {eval(\"/*@cc_on var aUIb0 = new Date() @*/\");aUIb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUIb0[\"get" ascii
    $s2  = "function aSe4(aODz8) {eval(\"/*@cc_on var aUIb0 = new Date() @*/\");aUIb0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUIb0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`H`a` `n`r`u`t`e`r`;`)`9`t`Q`a`(`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`k`U`S`a`=`9`t`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`e`H`a` `n`r`u`t`e`r`;`)`9`t`Q`a`(`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s8  = "onds\"]()[\"toString\"](10) == \"20\") {var aAXk2 = aODz8[\"split\"](\"`\"); return aAXk2[\"reverse\"]().join(\"\");} else retur" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`n`Z`L`a`;`)`2` `,`4`l`I`Q`a`(`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`g`r`6`g`m`z`v`/`l`n`.`l`a`a`t`e`m`n`i`e`l`k`r`e`m`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`s`V`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`3`b`m`e`f`1`n`x`w`v`/`m`o`c`.`o`b`a`l`-`s`w`e`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"/`*`@` `}`;`)`4`t`V`R`a`(`9`z`C`C`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`s`V`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`1`+`1`=`6`j`J`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\"/`*`@` `}`;`4`h`I`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`1`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSe4(\";`)`\\x22`m`f`a`6`0`v`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`t`n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}