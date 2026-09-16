rule sig_20161214_3e915249576415846853fa2f04c602b6 {
  meta:
    description = "datamaliciousorder - file 20161214_3e915249576415846853fa2f04c602b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84bc8cfe2e6e9fc1beec8dbfe8a003eb51ed740d69f898b6237fc725a33e4664"

  strings:
    $s1  = "function aCz3(aMi6) {eval(\"/*@cc_on var aYz8 = new Date() @*/\");aYz8[\"setUTCSeconds\"](\"0\", \"20\");if (aYz8.getUTCMillisec" ascii
    $s2  = "function aCz3(aMi6) {eval(\"/*@cc_on var aYz8 = new Date() @*/\");aYz8[\"setUTCSeconds\"](\"0\", \"20\");if (aYz8.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`0` `=` `4`j`N`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"/`*`@` `}`;`)`9`p`Y`R`a`(`0`s`T`T`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`1`+`1`=`8`n`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`t`M`a`;`)`2` `,`8`g`I`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"/`*`@` `}`;`6`i`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`v`S`V`a`=`9`h`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`t`M`a`;`)`2` `,`8`g`I`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "oString(10) == \"20\") {var aALx0 = aMi6[\"split\"](\"`\"); return aALx0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCz3(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}