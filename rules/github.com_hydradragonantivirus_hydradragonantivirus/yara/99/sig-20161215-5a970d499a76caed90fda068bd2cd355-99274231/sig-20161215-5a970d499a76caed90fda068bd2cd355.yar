rule sig_20161215_5a970d499a76caed90fda068bd2cd355 {
  meta:
    description = "datamaliciousorder - file 20161215_5a970d499a76caed90fda068bd2cd355.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77b2d75d3059f9b45c0bc3122c389666973fb912047e36069302be6fb4074e41"

  strings:
    $s1  = "function aLu1(aOm3) {eval(\"/*@cc_on var aLs3 = new Date() @*/\");aLs3[\"setUTCSeconds\"](\"0\", \"20\");if (aLs3.getUTCMillisec" ascii
    $s2  = "function aLu1(aOm3) {eval(\"/*@cc_on var aLs3 = new Date() @*/\");aLs3[\"setUTCSeconds\"](\"0\", \"20\");if (aLs3.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`k`c`n`t`k`k`a`/`m`o`c`.`e`r`a`i`l`i`b`o`m`m`i`e`n`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`F`U`a` `n`r`u`t`e`r`;`)`3`o`Y`G`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`F`U`a` `n`r`u`t`e`r`;`)`3`o`Y`G`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"/`*`@` `}`;`3`o`G`E`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`m`B`a`;`)`2` `,`9`h`I`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"/`*`@` `}`;`3`m`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"/`*`@` `}`;`3`m`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`t`O`E`a`=`3`o`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLu1(\"/`*`@` `}`;`5`o`S`Y`a` `n`r`u`t`e`r`;`}`;`)`1`b`U`M`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}