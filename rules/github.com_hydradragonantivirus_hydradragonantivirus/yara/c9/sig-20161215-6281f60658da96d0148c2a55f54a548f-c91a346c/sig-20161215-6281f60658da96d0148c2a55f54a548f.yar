rule sig_20161215_6281f60658da96d0148c2a55f54a548f {
  meta:
    description = "datamaliciousorder - file 20161215_6281f60658da96d0148c2a55f54a548f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d34fe927f754b1be77dde9fc3845089342daf01292976e9fc523075a04937318"

  strings:
    $s1  = "function aEy4(aTOm5) {eval(\"/*@cc_on var aMPj4 = new Date() @*/\");aMPj4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMPj4[\"get" ascii
    $s2  = "function aEy4(aTOm5) {eval(\"/*@cc_on var aMPj4 = new Date() @*/\");aMPj4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMPj4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`1`p`a`y`d`/`s`e`.`r`a`c`i`f`a`\\x22` `+` `2`r`K`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`0`l`x`y`u`q`a`q`d`/`k`d`.`l`o`b`m`y`s`i`r`e`l`l`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`o`V`J`a` `r`a`v` ` ` ` \"))," ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`m`W`H`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "onds\"]()[\"toString\"](10) == \"20\") {var aUWv7 = aTOm5[\"split\"](\"`\"); return aUWv7[\"reverse\"]().join(\"\");} else retur" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`1`+`1`=`3`p`P`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`m`W`H`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\"/`*`@` `}`;`7`y`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`q`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\"/`*`@` `}`;`5`m`O`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\"/`*`@` `}`;`)`7`w`A`J`a`(`6`e`H`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEy4(\";`0` `=` `8`m`Y`Z`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}