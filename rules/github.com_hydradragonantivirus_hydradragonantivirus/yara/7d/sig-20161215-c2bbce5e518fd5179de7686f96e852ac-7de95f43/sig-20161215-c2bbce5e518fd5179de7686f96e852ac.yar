rule sig_20161215_c2bbce5e518fd5179de7686f96e852ac {
  meta:
    description = "datamaliciousorder - file 20161215_c2bbce5e518fd5179de7686f96e852ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93a5ef9ccff3b190d50bc3793f30a9bd1cc8bc15e4cbd20f66d6f62bad588a52"

  strings:
    $s1  = "function aOv6(aGr2) {eval(\"/*@cc_on var aYe3 = new Date() @*/\");aYe3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYe3[\"getUTCM" ascii
    $s2  = "function aOv6(aGr2) {eval(\"/*@cc_on var aYe3 = new Date() @*/\");aYe3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aYe3[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`0`h`H`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`2`r`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`)`0`z`V`W`a`(`2`w`W`V`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`0`h`H`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `1`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`1`+`1`=`8`z`X`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`j`Y`Y`a`;`)`2` `,`9`t`W`A`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`m`J`C`a`=`2`r`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `1`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\";`1`+`1`=`8`z`X`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOv6(\"/`*`@` `}`;`8`d`O`a` `n`r`u`t`e`r`;`}`;`)`8`h`Q`G`a`(`]`\\x2" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}