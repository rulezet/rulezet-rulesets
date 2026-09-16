rule sig_20161215_5f0f6daea464958ca1d7adf9fc0cd82b {
  meta:
    description = "datamaliciousorder - file 20161215_5f0f6daea464958ca1d7adf9fc0cd82b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9cc82ec6ad226465dc62245ac52450c091508ee2053b3111be1f5fc638a9cc7"

  strings:
    $s1  = "function aXx1(aKFb0) {eval(\"/*@cc_on var aJTl9 = new Date() @*/\");aJTl9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJTl9[\"get" ascii
    $s2  = "function aXx1(aKFb0) {eval(\"/*@cc_on var aJTl9 = new Date() @*/\");aJTl9[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJTl9[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"}`;`h`t`a`P`t`r`o`h`S`.`4`u`I`T`a` `n`r`u`t`e`r`;`)`1`s`G`a`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` `" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`0`b`F`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`)`7`d`F`F`a`(`3`v`J`H`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`z`x`p`o`t`l`/`l`p`.`o`t`u`a`-`a`f`l`a`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`n`R`P`a`=`1`s`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`9`c`N`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`9`c`N`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`a`W`X`a`;`)`2` `,`5`m`K`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\"/`*`@` `}`;`6`e`W`I`a` `n`r`u`t`e`r`;`}`;`)`5`d`S`V`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXx1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}