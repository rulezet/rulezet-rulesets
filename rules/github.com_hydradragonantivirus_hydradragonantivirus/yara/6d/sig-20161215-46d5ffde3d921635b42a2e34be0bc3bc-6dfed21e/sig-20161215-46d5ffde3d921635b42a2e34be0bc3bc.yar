rule sig_20161215_46d5ffde3d921635b42a2e34be0bc3bc {
  meta:
    description = "datamaliciousorder - file 20161215_46d5ffde3d921635b42a2e34be0bc3bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3339d11b058009a6d105378679a9bfd18a01d72fda0e6b751b3749eb27e125b5"

  strings:
    $s1  = "function aBJt8(aTp2) {eval(\"/*@cc_on var aZd5 = new Date() @*/\");aZd5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZd5[\"getUTC" ascii
    $s2  = "function aBJt8(aTp2) {eval(\"/*@cc_on var aZd5 = new Date() @*/\");aZd5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZd5[\"getUTC" ascii
    $s3  = "s\"]()[\"toString\"](10) == \"20\") {var aMVx0 = aTp2[\"split\"](\"`\"); return aMVx0[\"reverse\"]().join(\"\");} else return \"" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`)`8`y`O`S`a`(`9`m`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"}`;`h`t`a`P`t`r`o`h`S`.`7`a`O`O`a` `n`r`u`t`e`r`;`)`4`y`G`S" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`r`Z`a`;`)`2` `,`2`q`L`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`0`x`V`M`a` `n`r`u`t`e`r`;`}`;`)`5`q`L`T`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"}`;`h`t`a`P`t`r`o`h`S`.`7`a`O`O`a` `n`r`u`t`e`r`;`)`4`y`G`S" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `4`i" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`)`8`y`O`S`a`(`9`m`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\"/`*`@` `}`;`2`p`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBJt8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `1`s`T`S`a` `r`a`v` `;" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}