rule sig_20161215_4c3ea2be52005aa76c99d57297043b18 {
  meta:
    description = "datamaliciousorder - file 20161215_4c3ea2be52005aa76c99d57297043b18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4e1a2ac6615913460db5d9399a6dc44beac89dc91dfb012f8fd2bd1c0834487"

  strings:
    $s1  = "function aGf1(aUw1) {eval(\"/*@cc_on var aEVp7 = new Date() @*/\");aEVp7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEVp7[\"getU" ascii
    $s2  = "function aGf1(aUw1) {eval(\"/*@cc_on var aEVp7 = new Date() @*/\");aEVp7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEVp7[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`1`i`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`h`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`k`C`a` `r`a`v` `;`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`b`V`a`;`)`2` `,`4`y`H`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s7  = "nds\"]()[\"toString\"](10) == \"20\") {var aIv5 = aUw1[\"split\"](\"`\"); return aIv5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`b`V`a`;`)`2` `,`4`y`H`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`5`v`I`a` `n`r`u`t`e`r`;`}`;`)`2`s`D`a`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`0` `=` `9`p`N`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`1`w`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\";`)`(`y`a`r`r`A` `w`e`n` `=` `4`e`A`E`a` `r`a`v` ` ` ` \"))," ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGf1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}