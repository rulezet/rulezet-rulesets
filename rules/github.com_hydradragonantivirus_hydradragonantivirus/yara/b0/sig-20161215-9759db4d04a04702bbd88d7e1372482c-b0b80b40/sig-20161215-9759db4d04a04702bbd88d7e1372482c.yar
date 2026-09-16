rule sig_20161215_9759db4d04a04702bbd88d7e1372482c {
  meta:
    description = "datamaliciousorder - file 20161215_9759db4d04a04702bbd88d7e1372482c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1472940e2018e8314becbcfbae873db9b839cffe659b859a89225b02f982f68f"

  strings:
    $s1  = "function aBVz2(aLEw3) {eval(\"/*@cc_on var aZXh9 = new Date() @*/\");aZXh9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZXh9[\"ge" ascii
    $s2  = "function aBVz2(aLEw3) {eval(\"/*@cc_on var aZXh9 = new Date() @*/\");aZXh9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZXh9[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`0` `=` `3`q`E`a` `r`a`v\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"/`*`@` `}`;`)`6`n`W`a`(`3`n`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`v`B`a`=`2`l`C" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"/`*`@` `}`;`)`6`n`W`a`(`3`n`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`o`V`a`;`)`2` `,`0`d`A`O`a`(`]" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`2`z`I`a` `+` `2`m`Y`a`=`2`v`B`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`1`+`1`=`0`y`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`n`W`N`a` `n`r`u`t`e`r`;`)`2`l`C`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`1`+`1`=`0`y`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`n`W`N`a` `n`r`u`t`e`r`;`)`2`l`C`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\"/`*`@` `}`;`8`j`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`g" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBVz2(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}