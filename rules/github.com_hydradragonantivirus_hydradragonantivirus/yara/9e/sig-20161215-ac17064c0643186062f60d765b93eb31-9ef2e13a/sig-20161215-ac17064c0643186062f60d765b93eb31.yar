rule sig_20161215_ac17064c0643186062f60d765b93eb31 {
  meta:
    description = "datamaliciousorder - file 20161215_ac17064c0643186062f60d765b93eb31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6c4278f4673a50bdf48a754465d7a9a8f1b6ffda0c2d11e43ede5d95e23f6ee"

  strings:
    $s1  = "function aVg3(aSGs4) {eval(\"/*@cc_on var aRLi4 = new Date() @*/\");aRLi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRLi4[\"get" ascii
    $s2  = "function aVg3(aSGs4) {eval(\"/*@cc_on var aRLi4 = new Date() @*/\");aRLi4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRLi4[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`6`t`J`I`a` `n`r`u`t`e`r`;`}`;`)`7`d`D`a`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`4`s`G`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s5  = "onds\"]()[\"toString\"](10) == \"20\") {var aIJt6 = aSGs4[\"split\"](\"`\"); return aIJt6[\"reverse\"]().join(\"\");} else retur" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`m`A`H`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`k`S`a`=`8`v`H`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`)`0`m`U`J`a`(`4`x`S`A`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`4`s`G`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`8`z`O`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\"/`*`@` `}`;`6`t`J`I`a` `n`r`u`t`e`r`;`}`;`)`7`d`D`a`(`]`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVg3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}