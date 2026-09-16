rule sig_20161215_6516b43c9a94bc891bde66a3c02fdc02 {
  meta:
    description = "datamaliciousorder - file 20161215_6516b43c9a94bc891bde66a3c02fdc02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edee98f32176753412ad2725d7be1aa6d57d94491dff52133fa7a784ae3724cf"

  strings:
    $s1  = "function aHw9(aAs6) {eval(\"/*@cc_on var aMGy1 = new Date() @*/\");aMGy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMGy1[\"getU" ascii
    $s2  = "function aHw9(aAs6) {eval(\"/*@cc_on var aMGy1 = new Date() @*/\");aMGy1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMGy1[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"/`*`@` `}`;`)`3`o`K`T`a`(`9`q`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s5  = "nds\"]()[\"toString\"](10) == \"20\") {var aDUs1 = aAs6[\"split\"](\"`\"); return aDUs1[\"reverse\"]().join(\"\");} else return " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`q`H`a` `r`a`v` `;`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"}`;`h`t`a`P`t`r`o`h`S`.`3`v`C`a` `n`r`u`t`e`r`;`)`7`y`C`Q`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`1`+`1`=`6`g`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`0` `=` `5`t`K`R`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"/`*`@` `}`;`)`3`o`K`T`a`(`9`q`A`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`k`Q`B`a`;`)`2` `,`8`s`Z`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"/`*`@` `}`;`1`s`U`D`a` `n`r`u`t`e`r`;`}`;`)`3`d`L`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`x`Q`a` `r`a`v` ` ` ` \")), 1" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`q`H`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHw9(\"/`*`@` `}`;`1`n`X`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}