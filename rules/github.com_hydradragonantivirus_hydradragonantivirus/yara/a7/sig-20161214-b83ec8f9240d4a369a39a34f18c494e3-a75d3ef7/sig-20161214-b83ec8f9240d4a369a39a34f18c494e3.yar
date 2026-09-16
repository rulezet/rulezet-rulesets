rule sig_20161214_b83ec8f9240d4a369a39a34f18c494e3 {
  meta:
    description = "datamaliciousorder - file 20161214_b83ec8f9240d4a369a39a34f18c494e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0d9a42ea27c64aaef88ac66e8fc2210d82502876139c0f03989773c38e5c092"

  strings:
    $s1  = "function aDv1(aKl0) {eval(\"/*@cc_on var aCd2 = new Date() @*/\");aCd2[\"setUTCSeconds\"](\"0\", \"20\");if (aCd2.getUTCMillisec" ascii
    $s2  = "function aDv1(aKl0) {eval(\"/*@cc_on var aCd2 = new Date() @*/\");aCd2[\"setUTCSeconds\"](\"0\", \"20\");if (aCd2.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`0`l`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`7`n`J`D`a` `n`r`u`t`e`r`;`}`;`)`6`u`E`a`(`]`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`0` `=` `2`b`Y`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `4`d`A`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s9  = "oString(10) == \"20\") {var aDJn7 = aKl0[\"split\"](\"`\"); return aDJn7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`b`F`a`;`)`2` `,`6`e`E`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`4`g`X`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`b`F`a`;`)`2` `,`6`e`E`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDv1(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}