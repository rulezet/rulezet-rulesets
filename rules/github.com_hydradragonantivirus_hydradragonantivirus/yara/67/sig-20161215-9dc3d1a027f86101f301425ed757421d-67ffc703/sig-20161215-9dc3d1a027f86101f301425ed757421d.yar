rule sig_20161215_9dc3d1a027f86101f301425ed757421d {
  meta:
    description = "datamaliciousorder - file 20161215_9dc3d1a027f86101f301425ed757421d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05d2ae0a0b50659e80ab3f5769d8aebe86972f3457c9d9122c4ad4175d30764a"

  strings:
    $s1  = "function aUIe7(aRLv0) {eval(\"/*@cc_on var aWXg6 = new Date() @*/\");aWXg6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWXg6[\"ge" ascii
    $s2  = "function aUIe7(aRLv0) {eval(\"/*@cc_on var aWXg6 = new Date() @*/\");aWXg6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWXg6[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`0`v`L`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`9`k`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`h" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`)`2`c`A`A`a`(`5`y`P`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`4`u`K`a` `+` `9`b`K`a`=`4`e`M`J`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`8`d`U`C`a` `n`r`u`t`e`r`;`}`;`)`5`b`R`M`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`0` `=` `6`l`L`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "conds\"]()[\"toString\"](10) == \"20\") {var aCUd8 = aRLv0[\"split\"](\"`\"); return aCUd8[\"reverse\"]().join(\"\");} else retu" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`0`v`L`R`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`8`d`U`C`a` `n`r`u`t`e`r`;`}`;`)`5`b`R`M`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\"/`*`@` `}`;`)`2`c`A`A`a`(`5`y`P`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUIe7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}