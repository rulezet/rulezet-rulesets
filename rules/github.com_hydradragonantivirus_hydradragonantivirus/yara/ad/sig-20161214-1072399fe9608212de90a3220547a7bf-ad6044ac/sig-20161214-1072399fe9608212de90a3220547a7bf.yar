rule sig_20161214_1072399fe9608212de90a3220547a7bf {
  meta:
    description = "datamaliciousorder - file 20161214_1072399fe9608212de90a3220547a7bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29f4b19749b14324b53cf5900d7e1e1f7cc15be6a36600e57462cf41c4ff09ad"

  strings:
    $s1  = "function aABi3(aAMw2) {eval(\"/*@cc_on var aWg7 = new Date() @*/\");aWg7[\"setUTCSeconds\"](\"0\", \"20\");if (aWg7.getUTCMillis" ascii
    $s2  = "function aABi3(aAMw2) {eval(\"/*@cc_on var aWg7 = new Date() @*/\");aWg7[\"setUTCSeconds\"](\"0\", \"20\");if (aWg7.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`2`w`M`A`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`1`+`1`=`8`y`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`h`T`W`a` `r`a`v` ` ` ` \"))" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`1`+`1`=`8`y`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`0` `=` `2`k`N`F`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`0`m`E`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`0`m`E`L`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`5`c`D`Q`a` `n`r`u`t`e`r`;`}`;`)`8`h`D`a`(`]`\\x" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`)`7`s`M`X`a`(`6`i`J`N`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`i`S`X`a`;`)`2` `,`5`i`K`a`(`]" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aABi3(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}