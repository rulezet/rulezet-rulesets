rule sig_20161215_7a3854f41785f58dcaf3212e3dff639a {
  meta:
    description = "datamaliciousorder - file 20161215_7a3854f41785f58dcaf3212e3dff639a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "070c71051fd929d954e39269cd2ecc90f9a3a69d3accf353e6d16b445514d99b"

  strings:
    $s1  = "function aHSn3(aMh6) {eval(\"/*@cc_on var aBNq0 = new Date() @*/\");aBNq0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBNq0[\"get" ascii
    $s2  = "function aHSn3(aMh6) {eval(\"/*@cc_on var aBNq0 = new Date() @*/\");aBNq0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aBNq0[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\"/`*`@` `}`;`1`w`O`U`a` `n`r`u`t`e`r`;`}`;`)`9`g`O`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\"/`*`@` `}`;`6`h`M`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`2`1`d`u`4`d`a`/`t`e`n`.`y`k`s`e`h`t`n`i`e`b`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`0`0`o`t`3`y`u`u`a`/`o`r`p`.`n`a`l`s`r`a`\\x22` `+" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`x`M`a` `r`a`v` ` ` ` \")), " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`3`e`C`a` `+` `2`s`X`a`=`9`n`G`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\"/`*`@` `}`;`3`r`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`t" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\"/`*`@` `}`;`1`w`O`U`a` `n`r`u`t`e`r`;`}`;`)`9`g`O`a`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`c`U`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`n`G`a`=`7`o`T" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`c`U`a` `r`a`v` `;`" ascii
    $s19 = "onds\"]()[\"toString\"](10) == \"20\") {var aUOw1 = aMh6[\"split\"](\"`\"); return aUOw1[\"reverse\"]().join(\"\");} else return" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHSn3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`n`G`a`=`7`o`T" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}