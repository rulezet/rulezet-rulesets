rule sig_20161214_a5e3042754cadac0b7eb70effa461764 {
  meta:
    description = "datamaliciousorder - file 20161214_a5e3042754cadac0b7eb70effa461764.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f04e99dc8f5352691e907ecb21d525343b58c0bdcb1dce9e6c5db51810bbcea7"

  strings:
    $s1  = "function aQIn4(aSo0) {eval(\"/*@cc_on var aLn6 = new Date() @*/\");aLn6[\"setUTCSeconds\"](\"0\", \"20\");if (aLn6.getUTCMillise" ascii
    $s2  = "function aQIn4(aSo0) {eval(\"/*@cc_on var aLn6 = new Date() @*/\");aLn6[\"setUTCSeconds\"](\"0\", \"20\");if (aLn6.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`0`o`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`0` `=` `2`o`H`D`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`u`J`R`a`=`4`k" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`s`M`J`a`;`)`2` `,`1`p`T`a`(`]" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`g`T`a` `r`a`v` ` ` ` \")), " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`)`9`t`N`a`(`9`r`V`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`8`h`C`S`a` `n`r`u`t`e`r`;`}`;`)`3`l`I`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`2`f`J`Y`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`1`+`1`=`7`p`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`1`+`1`=`7`p`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`2`b`U`F`a` `+` `1`o`K`H`a`=`8`u`J`R`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\"/`*`@` `}`;`)`9`t`N`a`(`9`r`V`K`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIn4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`u`J`R`a`=`4`k" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}