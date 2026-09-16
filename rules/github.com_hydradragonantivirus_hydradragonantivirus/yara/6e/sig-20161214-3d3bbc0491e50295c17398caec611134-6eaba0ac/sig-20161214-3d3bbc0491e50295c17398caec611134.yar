rule sig_20161214_3d3bbc0491e50295c17398caec611134 {
  meta:
    description = "datamaliciousorder - file 20161214_3d3bbc0491e50295c17398caec611134.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db547bccd928f512a3b04d3a31a8151258bf4c68ec4ab5ca7cb7ff60f97e00ed"

  strings:
    $s1  = "function aJg2(aJh0) {eval(\"/*@cc_on var aOMa4 = new Date() @*/\");aOMa4[\"setUTCSeconds\"](\"0\", \"20\");if (aOMa4.getUTCMilli" ascii
    $s2  = "function aJg2(aJh0) {eval(\"/*@cc_on var aOMa4 = new Date() @*/\");aOMa4[\"setUTCSeconds\"](\"0\", \"20\");if (aOMa4.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"/`*`@` `}`;`5`u`O`a` `n`r`u`t`e`r`;`}`;`)`7`z`W`a`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`x`B`a`;`)`2` `,`5`c`R`a`(`]`" ascii
    $s7  = ").toString(10) == \"20\") {var aOu5 = aJh0[\"split\"](\"`\"); return aOu5.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"/`*`@` `}`;`)`5`g`E`a`(`2`d`R`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"/`*`@` `}`;`4`c`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`c`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`t`B`a` `r`a`v` ` ` ` \")), 1" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`7`t`E`Y`a` `+` `8`g`O`V`a`=`3`n`I`T`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `5`q`V`B`a`(`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`n`I`T`a`=`5`y`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`g`G`a` `n`r`u`t`e`r`;`)`5`y`Y`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJg2(\"/`*`@` `}`;`4`c`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`c`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}