rule sig_20161214_9f0b04eaf05b725fda0dff61cd4fd58c {
  meta:
    description = "datamaliciousorder - file 20161214_9f0b04eaf05b725fda0dff61cd4fd58c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1195b39e2de76a48b83198aeace67f151db57891c754cd37d7500406f34984de"

  strings:
    $s1  = "function aBYq8(aHOl3) {eval(\"/*@cc_on var aPv2 = new Date() @*/\");aPv2[\"setUTCSeconds\"](\"0\", \"20\");if (aPv2.getUTCMillis" ascii
    $s2  = "function aBYq8(aHOl3) {eval(\"/*@cc_on var aPv2 = new Date() @*/\");aPv2[\"setUTCSeconds\"](\"0\", \"20\");if (aPv2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"/`*`@` `}`;`)`3`y`K`Y`a`(`1`q`G`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`0`y`N`a` `+` `2`d`P`a`=`9`m`B`M`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"/`*`@` `}`;`3`l`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`s" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`c`Q`a` `r`a`v` ` ` ` \")), " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"\")), 1);" fullword ascii
    $s14 = ".toString(10) == \"20\") {var aYRg0 = aHOl3[\"split\"](\"`\"); return aYRg0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\"/`*`@` `}`;`3`l`O`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`1`+`1`=`0`p`F`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBYq8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`m`B`M`a`=`4`p" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}