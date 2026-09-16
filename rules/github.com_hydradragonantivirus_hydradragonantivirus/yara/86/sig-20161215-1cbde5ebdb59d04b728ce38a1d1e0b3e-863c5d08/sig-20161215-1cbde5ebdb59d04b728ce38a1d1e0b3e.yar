rule sig_20161215_1cbde5ebdb59d04b728ce38a1d1e0b3e {
  meta:
    description = "datamaliciousorder - file 20161215_1cbde5ebdb59d04b728ce38a1d1e0b3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d44da7f8fc7f1c0bdfbc12ab1e77ec1278060c9b699f39629ffa4c6c4a254828"

  strings:
    $s1  = "function aIJq4(aWRw4) {eval(\"/*@cc_on var aUTz1 = new Date() @*/\");aUTz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTz1[\"ge" ascii
    $s2  = "function aIJq4(aWRw4) {eval(\"/*@cc_on var aUTz1 = new Date() @*/\");aUTz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUTz1[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`4`w`R`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`7`u`N`a`;`)`2` `,`3`g`G`a`(`]" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`3`m`L`O`a` `n`r`u`t`e`r`;`}`;`)`9`t`X`R`a`(`]`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`0`m`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`a" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`)`1`v`E`a`(`9`q`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`1`+`1`=`3`i`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s12 = "conds\"]()[\"toString\"](10) == \"20\") {var aOLm3 = aWRw4[\"split\"](\"`\"); return aOLm3[\"reverse\"]().join(\"\");} else retu" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`5`o`W`a` `+` `6`w`D`D`a`=`9`x`D`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`j`E`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`j`E`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`0`m`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIJq4(\"/`*`@` `}`;`)`1`v`E`a`(`9`q`S`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}