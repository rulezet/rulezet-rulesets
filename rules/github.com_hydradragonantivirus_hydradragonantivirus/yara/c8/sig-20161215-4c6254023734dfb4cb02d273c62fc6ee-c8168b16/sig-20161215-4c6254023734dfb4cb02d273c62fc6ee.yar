rule sig_20161215_4c6254023734dfb4cb02d273c62fc6ee {
  meta:
    description = "datamaliciousorder - file 20161215_4c6254023734dfb4cb02d273c62fc6ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "084beccbeda7f4c7974d56949186fbd0c53032dfc21c156e2f5684092aa59809"

  strings:
    $s1  = "function aWq3(aIg5) {eval(\"/*@cc_on var aLx9 = new Date() @*/\");aLx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLx9[\"getUTCM" ascii
    $s2  = "function aWq3(aIg5) {eval(\"/*@cc_on var aLx9 = new Date() @*/\");aLx9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLx9[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`k`Q`H`a`=`4`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"/`*`@` `}`;`5`g`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"}`;`h`t`a`P`t`r`o`h`S`.`8`x`G`a` `n`r`u`t`e`r`;`)`4`p`I`U`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `3`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`n`X`a`;`)`2` `,`4`p`O`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` `" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`b`R`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"/`*`@` `}`;`)`0`j`K`T`a`(`2`i`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\"/`*`@` `}`;`5`g`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`1`+`1`=`6`s`S`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWq3(\";`1`+`1`=`6`s`S`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}