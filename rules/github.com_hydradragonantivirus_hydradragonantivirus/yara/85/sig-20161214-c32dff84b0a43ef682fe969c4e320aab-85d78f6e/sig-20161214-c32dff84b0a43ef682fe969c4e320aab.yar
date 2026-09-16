rule sig_20161214_c32dff84b0a43ef682fe969c4e320aab {
  meta:
    description = "datamaliciousorder - file 20161214_c32dff84b0a43ef682fe969c4e320aab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3b1875180c366e56aba49d02a5d2a50333c07daec53e1a6e72fbbc64ce9a707"

  strings:
    $s1  = "function aIe7(aYv9) {eval(\"/*@cc_on var aXOp4 = new Date() @*/\");aXOp4[\"setUTCSeconds\"](\"0\", \"20\");if (aXOp4.getUTCMilli" ascii
    $s2  = "function aIe7(aYv9) {eval(\"/*@cc_on var aXOp4 = new Date() @*/\");aXOp4[\"setUTCSeconds\"](\"0\", \"20\");if (aXOp4.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`0`v`O`I`a` `+` `4`o`H`V`a`=`7`q`R`E`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`3`f`B`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`3`f`B`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`)`5`g`T`X`a`(`8`m`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`9`v`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"}`;`h`t`a`P`t`r`o`h`S`.`9`b`E`T`a` `n`r`u`t`e`r`;`)`5`d`H`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\"/`*`@` `}`;`4`p`V`a` `n`r`u`t`e`r`;`}`;`)`5`m`R`a`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `0`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aIe7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`q`R`E`a`=`5`d`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}