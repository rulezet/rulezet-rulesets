rule sig_20161215_7605c6f61697747f0072cbe873c32e66 {
  meta:
    description = "datamaliciousorder - file 20161215_7605c6f61697747f0072cbe873c32e66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94a31113c83c0a6c720cad9af309e82127819832cfcf676658991c6cc4dc629f"

  strings:
    $s1  = "function aZKu3(aFg8) {eval(\"/*@cc_on var aJNv2 = new Date() @*/\");aJNv2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJNv2[\"get" ascii
    $s2  = "function aZKu3(aFg8) {eval(\"/*@cc_on var aJNv2 = new Date() @*/\");aJNv2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aJNv2[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`\\x22`j`o`o`6`p`c`9`w`z`n`/`m`o`c`.`e`c`i`-`p`e`e`d`.`n" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`)`1`x`O`a`(`5`f`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`1`+`1`=`4`z`U`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`5`e`K`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`)`1`x`O`a`(`5`f`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`3`x`B`V`a` `n`r`u`t`e`r`;`}`;`)`6`r`E`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`3`x`B`V`a` `n`r`u`t`e`r`;`}`;`)`6`r`E`a`(`]`\\x" ascii
    $s13 = "onds\"]()[\"toString\"](10) == \"20\") {var aVBx3 = aFg8[\"split\"](\"`\"); return aVBx3[\"reverse\"]().join(\"\");} else return" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"/`*`@` `}`;`5`e`K`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\"}`;`h`t`a`P`t`r`o`h`S`.`9`x`S`Z`a` `n`r`u`t`e`r`;`)`8`y`A`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZKu3(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}