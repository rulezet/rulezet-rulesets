rule sig_20161215_b8c3ec0df2696cb10f9f9325a4f76b0d {
  meta:
    description = "datamaliciousorder - file 20161215_b8c3ec0df2696cb10f9f9325a4f76b0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "548860fde8c140e86b691c437ac35e816459507fc4edc4b4036a5e3ee6f220f5"

  strings:
    $s1  = "function aLl7(aDn9) {eval(\"/*@cc_on var aPNw9 = new Date() @*/\");aPNw9[\"setUTCSeconds\"](\"0\", \"20\");if (aPNw9.getUTCMilli" ascii
    $s2  = "function aLl7(aDn9) {eval(\"/*@cc_on var aPNw9 = new Date() @*/\");aPNw9[\"setUTCSeconds\"](\"0\", \"20\");if (aPNw9.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`h`I`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`z`M`U`a`=`9`u`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`z`M`U`a`=`9`u`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"/`*`@` `}`;`6`i`Q`O`a` `n`r`u`t`e`r`;`}`;`)`6`m`B`a`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"/`*`@` `}`;`6`i`Q`O`a` `n`r`u`t`e`r`;`}`;`)`6`m`B`a`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"/`*`@` `}`;`6`w`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`1`+`1`=`6`s`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`3`e`D`M`a` `+` `7`s`W`S`a`=`7`z`M`U`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `0`h`I`a`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`d`Q`a` `r`a`v` ` ` ` \")), 1" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLl7(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}