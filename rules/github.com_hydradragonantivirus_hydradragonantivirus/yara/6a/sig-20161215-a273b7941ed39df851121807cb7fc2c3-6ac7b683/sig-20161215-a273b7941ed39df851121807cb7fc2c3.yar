rule sig_20161215_a273b7941ed39df851121807cb7fc2c3 {
  meta:
    description = "datamaliciousorder - file 20161215_a273b7941ed39df851121807cb7fc2c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d87cad98462d621ae2a5a68cbee48fbf7963816aff5db7b3aaaacc5e610bbfb"

  strings:
    $s1  = "function aPr4(aXAv8) {eval(\"/*@cc_on var aFz0 = new Date() @*/\");aFz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFz0[\"getUTC" ascii
    $s2  = "function aPr4(aXAv8) {eval(\"/*@cc_on var aFz0 = new Date() @*/\");aFz0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aFz0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`9`n`P`Y`a` `n`r`u`t`e`r`;`}`;`)`8`s`T`a`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`0`z`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`d`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`x`X`a`;`)`2` `,`4`o`Z`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`0` `=` `0`u`E`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "s\"]()[\"toString\"](10) == \"20\") {var aYPn9 = aXAv8[\"split\"](\"`\"); return aYPn9[\"reverse\"]().join(\"\");} else return " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`x`A`O`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`8`v`A`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`0`z`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`d`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`6`p`A`D`a` `+` `1`i`I`a`=`3`g`P`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`g`P`a`=`5`l`I`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aPr4(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}