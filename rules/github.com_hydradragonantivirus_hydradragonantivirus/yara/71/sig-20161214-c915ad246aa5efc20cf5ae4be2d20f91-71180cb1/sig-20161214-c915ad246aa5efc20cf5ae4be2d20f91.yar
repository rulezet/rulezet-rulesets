rule sig_20161214_c915ad246aa5efc20cf5ae4be2d20f91 {
  meta:
    description = "datamaliciousorder - file 20161214_c915ad246aa5efc20cf5ae4be2d20f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5650ec8d6aba6fd3462f4015d6af18f17a2c583c1998de52eda622216ac86d3b"

  strings:
    $s1  = "function aUWv4(aLSn9) {eval(\"/*@cc_on var aGBg6 = new Date() @*/\");aGBg6[\"setUTCSeconds\"](\"0\", \"20\");if (aGBg6.getUTCMil" ascii
    $s2  = "function aUWv4(aLSn9) {eval(\"/*@cc_on var aGBg6 = new Date() @*/\");aGBg6[\"setUTCSeconds\"](\"0\", \"20\");if (aGBg6.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`)`9`v`N`U`a`(`1`g`S`I`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`9`n`S`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"}`;`h`t`a`P`t`r`o`h`S`.`5`m`R`a` `n`r`u`t`e`r`;`)`0`z`K`Q`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"}`;`h`t`a`P`t`r`o`h`S`.`5`m`R`a` `n`r`u`t`e`r`;`)`0`z`K`Q`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`u`f`s`7`h`/`m`o`c`.`l`o`r`b`o`g`n`k`u`y`\\x22` `+" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`0`f`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\"/`*`@` `}`;`9`x`Y`a` `n`r`u`t`e`r`;`}`;`)`4`r`F`B`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`n`N`T`a`=`0`z" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUWv4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}