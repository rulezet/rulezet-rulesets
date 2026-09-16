rule sig_20161215_07c95d345b85cdf5346031b4214677df {
  meta:
    description = "datamaliciousorder - file 20161215_07c95d345b85cdf5346031b4214677df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61959110634ed42cceaeadfdbb07fc45d408ff3b68ee9c19fcc5026ee1d6789"

  strings:
    $s1  = "function aVVl5(aMIl2) {eval(\"/*@cc_on var aNZj1 = new Date() @*/\");aNZj1[\"setUTCSeconds\"](\"0\", \"20\");if (aNZj1.getUTCMil" ascii
    $s2  = "function aVVl5(aMIl2) {eval(\"/*@cc_on var aNZj1 = new Date() @*/\");aNZj1[\"setUTCSeconds\"](\"0\", \"20\");if (aNZj1.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`0` `=` `9`a`Q`T`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`t`O`L`a` `r`a`v` ` ` ` \"))" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`1`+`1`=`9`i`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`2`l`I`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`0`r`S`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`3`q`D`a` `n`r`u`t`e`r`;`}`;`)`1`l`O`a`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`2`l`I`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`)`2`u`H`V`a`(`5`r`I`V`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVVl5(\"/`*`@` `}`;`3`q`D`a` `n`r`u`t`e`r`;`}`;`)`1`l`O`a`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}