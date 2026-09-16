rule sig_20161215_2b9e99c511855858a023a6e13263a66f {
  meta:
    description = "datamaliciousorder - file 20161215_2b9e99c511855858a023a6e13263a66f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343e1559b075867f0c23bdff0bc1469da43082fb878b4e12e0af8a6bd0964811"

  strings:
    $s1  = "function aIs9(aMWm1) {eval(\"/*@cc_on var aOw6 = new Date() @*/\");aOw6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOw6[\"getUTC" ascii
    $s2  = "function aIs9(aMWm1) {eval(\"/*@cc_on var aOw6 = new Date() @*/\");aOw6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aOw6[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"/`*`@` `}`;`)`7`w`G`J`a`(`2`c`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"}`;`h`t`a`P`t`r`o`h`S`.`1`t`W`N`a` `n`r`u`t`e`r`;`)`5`c`J`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"}`;`h`t`a`P`t`r`o`h`S`.`1`t`W`N`a` `n`r`u`t`e`r`;`)`5`c`J`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`1`+`1`=`0`f`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"/`*`@` `}`;`)`7`w`G`J`a`(`2`c`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`0` `=` `8`n`S`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`3`2`i`t`s`/`m`o`c`.`s`b`e`w`0`5`.`e`c`i`v`d`a`l`a`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s14 = "s\"]()[\"toString\"](10) == \"20\") {var aOVx0 = aMWm1[\"split\"](\"`\"); return aOVx0[\"reverse\"]().join(\"\");} else return " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`s`m`n`0`l`t`l`s`/`m`o`c`.`f`l`o`g`-`s`e`l`l`e`d`n`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`2`q`N`a` `+` `8`f`S`a`=`8`y`D`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`2`r`Q`a`;`)`2` `,`5`s`L`H`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `7`w`G`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIs9(\"/`*`@` `}`;`3`a`N`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}