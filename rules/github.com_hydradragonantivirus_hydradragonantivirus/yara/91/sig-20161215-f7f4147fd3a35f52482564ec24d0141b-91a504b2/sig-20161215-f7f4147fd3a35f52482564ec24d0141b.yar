rule sig_20161215_f7f4147fd3a35f52482564ec24d0141b {
  meta:
    description = "datamaliciousorder - file 20161215_f7f4147fd3a35f52482564ec24d0141b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96015110d717088984f35c2b066a67bfaa998d047f6af23c76d007d9b09659f3"

  strings:
    $s1  = "function aDOq7(aZp2) {eval(\"/*@cc_on var aUm6 = new Date() @*/\");aUm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUm6[\"getUTC" ascii
    $s2  = "function aDOq7(aZp2) {eval(\"/*@cc_on var aUm6 = new Date() @*/\");aUm6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aUm6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"/`*`@` `}`;`)`5`f`P`H`a`(`7`x`H`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`a`L`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`r`C`a`=`4`q`K" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"/`*`@` `}`;`2`p`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`1`+`1`=`7`s`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"/`*`@` `}`;`5`d`K`G`a` `n`r`u`t`e`r`;`}`;`)`5`v`L`A`a`(`]`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`a`L`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `1`t`U" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDOq7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`u`K`a` `n`r`u`t`e`r`;`)`4`q`K`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}