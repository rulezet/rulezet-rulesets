rule sig_20161214_bbf99c43f9a1aee06da19e3241841194 {
  meta:
    description = "datamaliciousorder - file 20161214_bbf99c43f9a1aee06da19e3241841194.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8e3115a0540203a2b3f8ed02cb26303998b2d3efc8d47b3c4b84587016d8987"

  strings:
    $s1  = "function aHNa1(aNHm2) {eval(\"/*@cc_on var aFMh0 = new Date() @*/\");aFMh0[\"setUTCSeconds\"](\"0\", \"20\");if (aFMh0.getUTCMil" ascii
    $s2  = "function aHNa1(aNHm2) {eval(\"/*@cc_on var aFMh0 = new Date() @*/\");aFMh0[\"setUTCSeconds\"](\"0\", \"20\");if (aFMh0.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`)`9`j`F`a`(`8`y`Z`T`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `8`m`T" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`6`c`R`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`2`q`I`a` `n`r`u`t`e`r`;`}`;`)`5`f`L`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `8`m`T" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`f`E`a` `r`a`v` ` ` ` \")), " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `8" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHNa1(\"/`*`@` `}`;`2`q`I`a` `n`r`u`t`e`r`;`}`;`)`5`f`L`a`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}