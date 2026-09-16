rule sig_20161214_d20e666331dfd9b9191c438aaa46f8e6 {
  meta:
    description = "datamaliciousorder - file 20161214_d20e666331dfd9b9191c438aaa46f8e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "045fcbccb25c264a63f7adc96aea741e4e107292bd95f2d31242390ca9caac85"

  strings:
    $s1  = "function aOa7(aDg0) {eval(\"/*@cc_on var aKr2 = new Date() @*/\");aKr2[\"setUTCSeconds\"](\"0\", \"20\");if (aKr2.getUTCMillisec" ascii
    $s2  = "function aOa7(aDg0) {eval(\"/*@cc_on var aKr2 = new Date() @*/\");aKr2[\"setUTCSeconds\"](\"0\", \"20\");if (aKr2.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"}`;`h`t`a`P`t`r`o`h`S`.`2`l`C`O`a` `n`r`u`t`e`r`;`)`6`c`M`M`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`w`C`a`=`6`c`M`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"/`*`@` `}`;`7`l`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`v`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`x`W`a`;`)`2` `,`1`n`Q`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"}`;`h`t`a`P`t`r`o`h`S`.`2`l`C`O`a` `n`r`u`t`e`r`;`)`6`c`M`M`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`1`+`1`=`2`x`P`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`1`+`1`=`2`x`P`J`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\"/`*`@` `}`;`)`3`q`S`K`a`(`7`s`L`D`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`s`K`Q`a` `r`a`v` ` ` ` \"))," ascii
    $s15 = "oString(10) == \"20\") {var aLJq0 = aDg0[\"split\"](\"`\"); return aLJq0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOa7(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}