rule sig_20161215_6352139819505dbebc823bce319d951e {
  meta:
    description = "datamaliciousorder - file 20161215_6352139819505dbebc823bce319d951e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d16e286fce9ad01664f46f8c336b8b69cdb0669e36ac30bf3e6971fbebf3a242"

  strings:
    $s1  = "function aDQr7(aQUi9) {eval(\"/*@cc_on var aNv7 = new Date() @*/\");aNv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNv7[\"getUT" ascii
    $s2  = "function aDQr7(aQUi9) {eval(\"/*@cc_on var aNv7 = new Date() @*/\");aNv7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aNv7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\"/`*`@` `}`;`2`u`Y`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`4`q`d`s`q`h`n`g`x`/`m`o`c`.`j`b`h`h`x`d`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`5`a`I`C`a` `+` `2`a`L`a`=`6`b`V`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`1`+`1`=`2`l`H`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\"/`*`@` `}`;`7`l`O`a` `n`r`u`t`e`r`;`}`;`)`0`d`E`B`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\"/`*`@` `}`;`)`4`h`P`V`a`(`2`e`O`U`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`b`V`a`=`0`v`R" ascii
    $s14 = "ds\"]()[\"toString\"](10) == \"20\") {var aOl7 = aQUi9[\"split\"](\"`\"); return aOl7[\"reverse\"]().join(\"\");} else return \"" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`k`Z`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`0`d`q`m`m`f`y`/`m`o`c`.`8`8`8`8`8`6`7`4`0`\\x22` " ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`p`c`6`k`7`/`u`r`.`t`s`u`d`-`i`t`n`a`\\x22` `+` `2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\";`)`\\x22`x`w`8`o`n`x`/`n`c`.`m`o`c`.`n`o`i`t`a`v`e`l`e`.`w" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDQr7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}