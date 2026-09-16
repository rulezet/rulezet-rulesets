rule sig_20161214_a0952d336b1cb3f8f741ae7e60b8f5cf {
  meta:
    description = "datamaliciousorder - file 20161214_a0952d336b1cb3f8f741ae7e60b8f5cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a812bbc6768c81aa4e6e900e77e22884905fbeda641e5b61a160313b89a80502"

  strings:
    $s1  = "function aHOv6(aSGu1) {eval(\"/*@cc_on var aIEs4 = new Date() @*/\");aIEs4[\"setUTCSeconds\"](\"0\", \"20\");if (aIEs4.getUTCMil" ascii
    $s2  = "function aHOv6(aSGu1) {eval(\"/*@cc_on var aIEs4 = new Date() @*/\");aIEs4[\"setUTCSeconds\"](\"0\", \"20\");if (aIEs4.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`q`R`U`a`;`)`2` `,`1`i`J`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`0` `=` `5`z`E`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`1`u`G`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`1`+`1`=`6`u`S`M`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`1`u`G`S`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`h`Y`S`a` `r`a`v` ` ` ` \"))" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`)`9`y`R`D`a`(`7`y`N`S`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`x`T`V`a`=`2`m" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`2`x`D`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHOv6(\"/`*`@` `}`;`8`q`P`B`a` `n`r`u`t`e`r`;`}`;`)`7`s`F`a`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}