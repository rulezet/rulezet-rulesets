rule sig_20161215_ee456d067ab2efaa1781ad77af78a21c {
  meta:
    description = "datamaliciousorder - file 20161215_ee456d067ab2efaa1781ad77af78a21c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae749050edde3dfdb28ea861908157af4d6e4e40ee084ac0a1f58b319fa22720"

  strings:
    $s1  = "function aBe7(aVh3) {eval(\"/*@cc_on var aYj3 = new Date() @*/\");aYj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYj3[\"getUTCM" ascii
    $s2  = "function aBe7(aVh3) {eval(\"/*@cc_on var aYj3 = new Date() @*/\");aYj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYj3[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`3`h`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`9`n`B`a` `n`r`u`t`e`r`;`}`;`)`0`d`A`M`a`(`]`\\x2" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`8`n`V`U`a` `+` `8`k`V`X`a`=`8`k`Q`E`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`1`g`G`R`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`1`+`1`=`7`n`Z`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`4`x`p`s`u`s`c`n`/`m`o`c`.`s`b`e`w`0`5`.`d`e`l`t`i`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`)`6`c`Z`J`a`(`8`j`P`L`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`f`W`H`a`;`)`2` `,`4`f`F`a`(`]`" ascii
    $s18 = "\"]()[\"toString\"](10) == \"20\") {var aBn9 = aVh3[\"split\"](\"`\"); return aBn9[\"reverse\"]().join(\"\");} else return \"\";" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\"/`*`@` `}`;`3`h`V`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBe7(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}