rule sig_20161215_77e4fc6d078ced11e539316900dd51b4 {
  meta:
    description = "datamaliciousorder - file 20161215_77e4fc6d078ced11e539316900dd51b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97c7910190dc80d83d45853dfb7bbba769769368a1698ce8c4ecd846e258c58f"

  strings:
    $s1  = "function aNt3(aTo5) {eval(\"/*@cc_on var aRc5 = new Date() @*/\");aRc5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRc5[\"getUTCM" ascii
    $s2  = "function aNt3(aTo5) {eval(\"/*@cc_on var aRc5 = new Date() @*/\");aRc5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRc5[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `3`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"}`;`h`t`a`P`t`r`o`h`S`.`9`m`P`I`a` `n`r`u`t`e`r`;`)`8`u`H`N`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`)`3`f`U`a`(`3`l`D`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`)`3`f`U`a`(`3`l`D`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`f`O`a` `r`a`v` `;`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`1`w`B`a` `n`r`u`t`e`r`;`}`;`)`6`t`S`a`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`r`H`B`a`;`)`2` `,`9`z`E`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`1`+`1`=`8`m`O`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`5`o`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`f`O`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`0`n`Q`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\";`)`\\x22`g`v`j`j`y`/`m`o`c`.`c`e`l`e`s`e`k`y`d`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNt3(\"/`*`@` `}`;`0`n`Q`O`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}