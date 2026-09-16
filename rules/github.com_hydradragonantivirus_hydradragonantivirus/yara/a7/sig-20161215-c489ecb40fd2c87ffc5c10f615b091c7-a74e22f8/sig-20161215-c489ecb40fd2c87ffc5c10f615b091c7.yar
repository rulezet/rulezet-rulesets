rule sig_20161215_c489ecb40fd2c87ffc5c10f615b091c7 {
  meta:
    description = "datamaliciousorder - file 20161215_c489ecb40fd2c87ffc5c10f615b091c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9e956b0736ee23dd4838cc16dce48b912ed9cef307902b07c22a963685a3de"

  strings:
    $s1  = "function aUq1(aCDj0) {eval(\"/*@cc_on var aSl0 = new Date() @*/\");aSl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSl0[\"getUTC" ascii
    $s2  = "function aUq1(aCDj0) {eval(\"/*@cc_on var aSl0 = new Date() @*/\");aSl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSl0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\"/`*`@` `}`;`)`7`s`N`G`a`(`3`x`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`c`J`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` `" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`1`+`1`=`4`j`V`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`v`q`n`m`f`0`/`m`o`c`.`s`o`t`o`h`p`o`z`\\x22` `+` `" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`a`i`v`p`e`c`0`/`e`d`.`a`v`i`d`-`s`l`e`g`n`a`-`n`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`w`U`A`a` `r`a`v` ` ` ` \"))," ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s18 = "s\"]()[\"toString\"](10) == \"20\") {var aIi7 = aCDj0[\"split\"](\"`\"); return aIi7[\"reverse\"]().join(\"\");} else return \"" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`k`V`a`;`)`2` `,`7`d`M`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUq1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}