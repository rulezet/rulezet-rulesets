rule sig_20161214_b29564630d3437b7ed617d9b48e91976 {
  meta:
    description = "datamaliciousorder - file 20161214_b29564630d3437b7ed617d9b48e91976.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea0e00f2d73b7d2882c8641659a0a7c0af985978583215e8ac2ad9baecc56404"

  strings:
    $s1  = "function aOh0(aRVc2) {eval(\"/*@cc_on var aTk4 = new Date() @*/\");aTk4[\"setUTCSeconds\"](\"0\", \"20\");if (aTk4.getUTCMillise" ascii
    $s2  = "function aOh0(aRVc2) {eval(\"/*@cc_on var aTk4 = new Date() @*/\");aTk4[\"setUTCSeconds\"](\"0\", \"20\");if (aTk4.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"}`;`h`t`a`P`t`r`o`h`S`.`6`f`G`M`a` `n`r`u`t`e`r`;`)`7`x`G`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`1`+`1`=`7`l`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"/`*`@` `}`;`2`c`V`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`1`+`1`=`7`l`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`j`F`Y`a`=`7`x`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`Y`S`a`;`)`2` `,`7`z`G`T`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"/`*`@` `}`;`)`6`p`K`a`(`7`e`I`a` `n`r`u`t`e`r`;`)`(`e`s`o`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`Y`S`a`;`)`2` `,`7`z`G`T`a`(`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOh0(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}