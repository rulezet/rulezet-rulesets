rule sig_20161215_712bbbcec83dd9393a32958acf1d54f2 {
  meta:
    description = "datamaliciousorder - file 20161215_712bbbcec83dd9393a32958acf1d54f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04a60ab2f5c680881b5c6f0453446facc40af7023aa03c5c06d000b9102ad628"

  strings:
    $s1  = "function aFRj8(aPDy4) {eval(\"/*@cc_on var aVf7 = new Date() @*/\");aVf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVf7[\"getUT" ascii
    $s2  = "function aFRj8(aPDy4) {eval(\"/*@cc_on var aVf7 = new Date() @*/\");aVf7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVf7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`k`U`S`a` `n`r`u`t`e`r`;`)`2`s`H`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `1`n`Y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`1`+`1`=`0`p`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`4`y`D`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`d`J`M`a`=`2`s" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`f`K`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`5`v`G`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9" ascii
    $s13 = "ds\"]()[\"toString\"](10) == \"20\") {var aDj2 = aPDy4[\"split\"](\"`\"); return aDj2[\"reverse\"]().join(\"\");} else return \"" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`)`3`c`V`G`a`(`4`w`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`2`j`D`a` `n`r`u`t`e`r`;`}`;`)`7`w`V`a`(`]`\\x22" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"}`;`h`t`a`P`t`r`o`h`S`.`2`k`U`S`a` `n`r`u`t`e`r`;`)`2`s`H`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRj8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`v`U`a`;`)`2` `,`7`z`H`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}