rule sig_20161214_d795449cdcf4e138b6575e6e473bea6f {
  meta:
    description = "datamaliciousorder - file 20161214_d795449cdcf4e138b6575e6e473bea6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "325b727735f46ed25d2804678d6c9569fdf694b03f8853b43528bc77824ea7df"

  strings:
    $s1  = "function aNBo2(aXz7) {eval(\"/*@cc_on var aDMs2 = new Date() @*/\");aDMs2[\"setUTCSeconds\"](\"0\", \"20\");if (aDMs2.getUTCMill" ascii
    $s2  = "function aNBo2(aXz7) {eval(\"/*@cc_on var aDMs2 = new Date() @*/\");aDMs2[\"setUTCSeconds\"](\"0\", \"20\");if (aDMs2.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`8`v`K`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`1`+`1`=`8`c`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`)`0`g`B`a`(`0`d`E`P`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`4`c`G`Q`a` `n`r`u`t`e`r`;`}`;`)`8`u`V`W`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`0` `=` `7`x`J`Z`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`4`c`G`Q`a` `n`r`u`t`e`r`;`}`;`)`8`u`V`W`a`(`]`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`b`D`a`=`5`o`J" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `7" ascii
    $s19 = "().toString(10) == \"20\") {var aQGc4 = aXz7[\"split\"](\"`\"); return aQGc4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNBo2(\"/`*`@` `}`;`7`z`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}