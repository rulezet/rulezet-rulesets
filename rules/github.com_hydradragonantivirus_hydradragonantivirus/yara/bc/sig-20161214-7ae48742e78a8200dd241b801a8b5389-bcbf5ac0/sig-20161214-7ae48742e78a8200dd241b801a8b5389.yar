rule sig_20161214_7ae48742e78a8200dd241b801a8b5389 {
  meta:
    description = "datamaliciousorder - file 20161214_7ae48742e78a8200dd241b801a8b5389.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7e700934b4964db4ce8c61a8738cec523024c532f8e7d5486a3d5cf83196f44"

  strings:
    $s1  = "function aBRx3(aGAg0) {eval(\"/*@cc_on var aVu6 = new Date() @*/\");aVu6[\"setUTCSeconds\"](\"0\", \"20\");if (aVu6.getUTCMillis" ascii
    $s2  = "function aBRx3(aGAg0) {eval(\"/*@cc_on var aVu6 = new Date() @*/\");aVu6[\"setUTCSeconds\"](\"0\", \"20\");if (aVu6.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"}`;`h`t`a`P`t`r`o`h`S`.`2`k`T`Q`a` `n`r`u`t`e`r`;`)`8`x`N`Q" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`0`g`A`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`5`h`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`r" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`q`O`J`a`=`8`x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`)`9`v`L`a`(`2`d`O`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBRx3(\"/`*`@` `}`;`5`h`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}