rule sig_20161214_5f87ead61d32d96a9b49874e523a1961 {
  meta:
    description = "datamaliciousorder - file 20161214_5f87ead61d32d96a9b49874e523a1961.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bba889e94e931bc4de6ec6fade200e20430d8e225e96f05da4f9dacdf343ebf"

  strings:
    $s1  = "function aNGz5(aKz5) {eval(\"/*@cc_on var aEr1 = new Date() @*/\");aEr1[\"setUTCSeconds\"](\"0\", \"20\");if (aEr1.getUTCMillise" ascii
    $s2  = "function aNGz5(aKz5) {eval(\"/*@cc_on var aEr1 = new Date() @*/\");aEr1[\"setUTCSeconds\"](\"0\", \"20\");if (aEr1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`b`S`M`a`=`1`y" ascii
    $s4  = "toString(10) == \"20\") {var aFMc7 = aKz5[\"split\"](\"`\"); return aFMc7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`h`G`a` `r`a`v` ` ` ` \")), " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`z`G`Z`a`;`)`2` `,`0`k`G`U`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"}`;`h`t`a`P`t`r`o`h`S`.`2`h`M`a` `n`r`u`t`e`r`;`)`1`y`F`a`(" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"/`*`@` `}`;`)`2`o`J`a`(`2`c`K`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`b`S`M`a`=`1`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\"/`*`@` `}`;`7`c`M`F`a` `n`r`u`t`e`r`;`}`;`)`7`n`Q`W`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNGz5(\";`8`h`A`a` `+` `3`s`V`a`=`1`b`S`M`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}