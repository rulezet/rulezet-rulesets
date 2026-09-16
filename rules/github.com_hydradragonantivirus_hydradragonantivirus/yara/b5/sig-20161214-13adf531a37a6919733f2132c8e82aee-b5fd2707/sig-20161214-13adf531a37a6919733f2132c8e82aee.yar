rule sig_20161214_13adf531a37a6919733f2132c8e82aee {
  meta:
    description = "datamaliciousorder - file 20161214_13adf531a37a6919733f2132c8e82aee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc938dd9dd76772f5372d9f03c6eca8045394941f797c48986e510bcb81b342f"

  strings:
    $s1  = "function aRu7(aUm2) {eval(\"/*@cc_on var aYVk4 = new Date() @*/\");aYVk4[\"setUTCSeconds\"](\"0\", \"20\");if (aYVk4.getUTCMilli" ascii
    $s2  = "function aRu7(aUm2) {eval(\"/*@cc_on var aYVk4 = new Date() @*/\");aYVk4[\"setUTCSeconds\"](\"0\", \"20\");if (aYVk4.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\"\")), 1);" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\"/`*`@` `}`;`3`f`S`K`a` `n`r`u`t`e`r`;`}`;`)`7`b`P`D`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`0` `=` `7`j`V`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`l`I`X`a`;`)`2` `,`0`g`O`Q`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\"}`;`h`t`a`P`t`r`o`h`S`.`2`j`K`a` `n`r`u`t`e`r`;`)`9`k`T`a`(`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = ").toString(10) == \"20\") {var aKSf3 = aUm2[\"split\"](\"`\"); return aKSf3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `9`a`M`a`(`h`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`3`q`Q`a` `+` `9`j`J`Q`a`=`1`f`O`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `9`a`M`a`(`h`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aRu7(\";`1`+`1`=`5`l`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}