rule sig_20161215_932dda2439cb460b4b69768c2d8b63a8 {
  meta:
    description = "datamaliciousorder - file 20161215_932dda2439cb460b4b69768c2d8b63a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "497a518145b18a3c967e632c5a2e91a676f5c42cdd8a0589e34f7ffde7a77325"

  strings:
    $s1  = "function aHWc2(aHQn0) {eval(\"/*@cc_on var aSZt1 = new Date() @*/\");aSZt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSZt1[\"ge" ascii
    $s2  = "function aHWc2(aHQn0) {eval(\"/*@cc_on var aSZt1 = new Date() @*/\");aSZt1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aSZt1[\"ge" ascii
    $s3  = "conds\"]()[\"toString\"](10) == \"20\") {var aOg6 = aHQn0[\"split\"](\"`\"); return aOg6[\"reverse\"]().join(\"\");} else return" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`s`I`X`a`;`)`2` `,`3`m`J`a`(`]" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`s`I`X`a`;`)`2` `,`3`m`J`a`(`]" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`1`+`1`=`2`s`G`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`s`S`a` `n`r`u`t`e`r`;`)`8`z`I`W`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`0`n`Q`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`n`z`i`c`m`h`2`m`/`m`o`c`.`p`a`s`a`k`n`a`k`a`t`a`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`1`n`I`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"/`*`@` `}`;`1`n`I`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\"}`;`h`t`a`P`t`r`o`h`S`.`5`s`S`a` `n`r`u`t`e`r`;`)`8`z`I`W`a" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHWc2(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}