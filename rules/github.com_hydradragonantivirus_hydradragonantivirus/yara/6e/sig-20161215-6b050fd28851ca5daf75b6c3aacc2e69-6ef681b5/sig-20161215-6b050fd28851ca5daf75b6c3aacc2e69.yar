rule sig_20161215_6b050fd28851ca5daf75b6c3aacc2e69 {
  meta:
    description = "datamaliciousorder - file 20161215_6b050fd28851ca5daf75b6c3aacc2e69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04c8039a99fad3cf8f68a90831e72c9ac958891499e5b255b124f344dfb4d14d"

  strings:
    $s1  = "function aUv6(aICg3) {eval(\"/*@cc_on var aPZl0 = new Date() @*/\");aPZl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPZl0[\"get" ascii
    $s2  = "function aUv6(aICg3) {eval(\"/*@cc_on var aPZl0 = new Date() @*/\");aPZl0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aPZl0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"}`;`h`t`a`P`t`r`o`h`S`.`8`g`Y`R`a` `n`r`u`t`e`r`;`)`6`b`Q`D`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`0` `=` `1`j`W`S`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "onds\"]()[\"toString\"](10) == \"20\") {var aVi0 = aICg3[\"split\"](\"`\"); return aVi0[\"reverse\"]().join(\"\");} else return " ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"/`*`@` `}`;`3`g`C`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"/`*`@` `}`;`3`g`C`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"/`*`@` `}`;`0`i`V`a` `n`r`u`t`e`r`;`}`;`)`5`e`V`a`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"/`*`@` `}`;`0`i`V`a` `n`r`u`t`e`r`;`}`;`)`5`e`V`a`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`1`+`1`=`9`d`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`\\x22`h`k`m`s`y`2`4`b`t`f`/`t`e`n`.`u`t`n`a`u`h`c`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`v`Z`H`a`=`6`b`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\"\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`w`W`Y`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUv6(\";`)`\\x22`t`w`e`x`d`z`f`/`s`e`.`p`r`a`h`s`s`a`r`o`d`a`i`p`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}