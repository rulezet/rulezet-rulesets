rule sig_20161214_032b5cfa8da9909cfa64036f45d6284b {
  meta:
    description = "datamaliciousorder - file 20161214_032b5cfa8da9909cfa64036f45d6284b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa33a5044ad534de135343c2f0f4c80e6c8ee164d92419db2da8bb53180fec7b"

  strings:
    $s1  = "function aDk2(aQb6) {eval(\"/*@cc_on var aTp4 = new Date() @*/\");aTp4[\"setUTCSeconds\"](\"0\", \"20\");if (aTp4.getUTCMillisec" ascii
    $s2  = "function aDk2(aQb6) {eval(\"/*@cc_on var aTp4 = new Date() @*/\");aTp4[\"setUTCSeconds\"](\"0\", \"20\");if (aTp4.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`6`b`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`q`M`a`=`1`y`Z`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`5`y`W`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`d`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"}`;`h`t`a`P`t`r`o`h`S`.`8`u`D`a` `n`r`u`t`e`r`;`)`1`y`Z`Y`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`)`5`p`E`L`a`(`8`a`S`R`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`4`i`U`a` `n`r`u`t`e`r`;`}`;`)`7`f`V`a`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`4`i`U`a` `n`r`u`t`e`r`;`}`;`)`7`f`V`a`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`o`9`f`n`c`4`w`s`z`/`u`r`.`r`e`k`a`r`b`e`l`u`r`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aDk2(\";`)`\\x22`c`o`9`o`e`e`/`n`i`.`e`l`t`t`u`h`s`-`b`e`w`\\x22` `" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}