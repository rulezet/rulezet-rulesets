rule sig_20161214_8a149470384982044708117cfb590365 {
  meta:
    description = "datamaliciousorder - file 20161214_8a149470384982044708117cfb590365.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d36f5d1f4aaaa89377f98aa9153928ac532b28f8a33786d06b3276a0ddce393f"

  strings:
    $s1  = "function aPCz8(aAk0) {eval(\"/*@cc_on var aDy9 = new Date() @*/\");aDy9[\"setUTCSeconds\"](\"0\", \"20\");if (aDy9.getUTCMillise" ascii
    $s2  = "function aPCz8(aAk0) {eval(\"/*@cc_on var aDy9 = new Date() @*/\");aDy9[\"setUTCSeconds\"](\"0\", \"20\");if (aDy9.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\"/`*`@` `}`;`7`h`J`W`a` `n`r`u`t`e`r`;`}`;`)`9`u`K`a`(`]`\\x" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`5`q`Z`B`a` `+` `0`t`Z`a`=`3`b`N`X`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "toString(10) == \"20\") {var aWJh7 = aAk0[\"split\"](\"`\"); return aWJh7.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\"/`*`@` `}`;`)`4`c`L`a`(`7`s`J`I`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`n`R`O`a`;`)`2` `,`9`m`Y`K`a`(" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`1`+`1`=`2`k`T`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`n`R`O`a`;`)`2` `,`9`m`Y`K`a`(" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPCz8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}