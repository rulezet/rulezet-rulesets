rule sig_20161215_ae8cfdd634c37241a3220b3d9230ba8c {
  meta:
    description = "datamaliciousorder - file 20161215_ae8cfdd634c37241a3220b3d9230ba8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a40a11d4a2febc583918f01aacbd130938174c2993c793b27349106be1837aef"

  strings:
    $s1  = "function aLWe1(aKNk2) {eval(\"/*@cc_on var aSFa1 = new Date() @*/\");aSFa1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSFa1[\"ge" ascii
    $s2  = "function aLWe1(aKNk2) {eval(\"/*@cc_on var aSFa1 = new Date() @*/\");aSFa1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSFa1[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`1`+`1`=`9`b`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`6`i`D`a` `+` `9`m`V`F`a`=`1`e`I`A`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`a`T`a`;`)`2` `,`6`m`G`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`a`T`a`;`)`2` `,`6`m`G`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`r`A`a` `r`a`v` `;`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`2`k`N`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`2`j`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`q" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`2`k`N`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\"/`*`@` `}`;`)`6`r`V`a`(`7`i`U`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLWe1(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}