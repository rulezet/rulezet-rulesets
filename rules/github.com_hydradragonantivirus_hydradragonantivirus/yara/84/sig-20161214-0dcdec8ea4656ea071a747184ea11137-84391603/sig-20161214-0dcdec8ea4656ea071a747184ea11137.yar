rule sig_20161214_0dcdec8ea4656ea071a747184ea11137 {
  meta:
    description = "datamaliciousorder - file 20161214_0dcdec8ea4656ea071a747184ea11137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3488d3784616cd85cb41d9ca3bc204d7f88bf1557ca26cfa9e9af729e11bfa"

  strings:
    $s1  = "function aQVe3(aLBk6) {eval(\"/*@cc_on var aUf2 = new Date() @*/\");aUf2[\"setUTCSeconds\"](\"0\", \"20\");if (aUf2.getUTCMillis" ascii
    $s2  = "function aQVe3(aLBk6) {eval(\"/*@cc_on var aUf2 = new Date() @*/\");aUf2[\"setUTCSeconds\"](\"0\", \"20\");if (aUf2.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`\\x22`u`4`2`k`j`z`z`w`8`/`i`a`1`p`-`-`n`x`.`e`f`e`f`f`a" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`o`I`I`a` `r`a`v` ` ` ` \"))" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`w`X`V`a`;`)`2` `,`0`m`V`a`(`]" ascii
    $s7  = ".toString(10) == \"20\") {var aCy3 = aLBk6[\"split\"](\"`\"); return aCy3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`z`U`a`=`1`n`Q" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`)`1`w`P`I`a`(`1`o`J`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`3`t`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`r" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`6`k`B`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\"/`*`@` `}`;`3`y`C`a` `n`r`u`t`e`r`;`}`;`)`2`k`N`a`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `6`x`R" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `6`x`R" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQVe3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}