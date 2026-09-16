rule sig_20161214_2baa4d53e57bc98eb8131109da24f916 {
  meta:
    description = "datamaliciousorder - file 20161214_2baa4d53e57bc98eb8131109da24f916.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aeaffad0c7f6db324d6d84bd7c287bd611c584c7e27c76b2db99229f09065f1"

  strings:
    $s1  = "function aLr4(aFb8) {eval(\"/*@cc_on var aYe2 = new Date() @*/\");aYe2[\"setUTCSeconds\"](\"0\", \"20\");if (aYe2.getUTCMillisec" ascii
    $s2  = "function aLr4(aFb8) {eval(\"/*@cc_on var aYe2 = new Date() @*/\");aYe2[\"setUTCSeconds\"](\"0\", \"20\");if (aYe2.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`v`L`P`a`;`)`2` `,`3`t`S`a`(`]`" ascii
    $s4  = "oString(10) == \"20\") {var aEh2 = aFb8[\"split\"](\"`\"); return aEh2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`8`b`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`g`C`A`a` `r`a`v` ` ` ` \"))," ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`2`h`E`a` `n`r`u`t`e`r`;`}`;`)`3`h`U`N`a`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`1`+`1`=`9`r`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`)`4`k`E`a`(`3`e`C`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`v`L`P`a`;`)`2` `,`3`t`S`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLr4(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}