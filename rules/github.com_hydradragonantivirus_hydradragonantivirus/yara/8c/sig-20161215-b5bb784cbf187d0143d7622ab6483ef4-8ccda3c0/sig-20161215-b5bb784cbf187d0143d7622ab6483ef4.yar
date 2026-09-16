rule sig_20161215_b5bb784cbf187d0143d7622ab6483ef4 {
  meta:
    description = "datamaliciousorder - file 20161215_b5bb784cbf187d0143d7622ab6483ef4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90110530a692112d6a27d504deddd6f2ff31f6a26221ffe08cc3671fb51f3dee"

  strings:
    $s1  = "function aWRl1(aUb2) {eval(\"/*@cc_on var aKa9 = new Date() @*/\");aKa9[\"setUTCSeconds\"](\"0\", \"20\");if (aKa9.getUTCMillise" ascii
    $s2  = "function aWRl1(aUb2) {eval(\"/*@cc_on var aKa9 = new Date() @*/\");aKa9[\"setUTCSeconds\"](\"0\", \"20\");if (aKa9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "toString(10) == \"20\") {var aPDz5 = aUb2[\"split\"](\"`\"); return aPDz5.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`z`L`F`a`=`2`i" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"/`*`@` `}`;`6`e`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`a" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`x`R`X`a`;`)`2` `,`3`a`B`L`a`(" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`v`H`a` `r`a`v` ` ` ` \")), " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"/`*`@` `}`;`5`z`D`P`a` `n`r`u`t`e`r`;`}`;`)`6`j`L`N`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWRl1(\"/`*`@` `}`;`2`b`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}