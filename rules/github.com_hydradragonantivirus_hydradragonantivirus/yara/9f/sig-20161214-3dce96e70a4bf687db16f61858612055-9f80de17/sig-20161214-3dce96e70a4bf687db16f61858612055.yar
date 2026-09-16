rule sig_20161214_3dce96e70a4bf687db16f61858612055 {
  meta:
    description = "datamaliciousorder - file 20161214_3dce96e70a4bf687db16f61858612055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c8350aec8e78bc57a982582d3bbabf367bb2feaedd98caa752f59bc8626bf9e"

  strings:
    $s1  = "function aYf2(aZn8) {eval(\"/*@cc_on var aRKe9 = new Date() @*/\");aRKe9[\"setUTCSeconds\"](\"0\", \"20\");if (aRKe9.getUTCMilli" ascii
    $s2  = "function aYf2(aZn8) {eval(\"/*@cc_on var aRKe9 = new Date() @*/\");aRKe9[\"setUTCSeconds\"](\"0\", \"20\");if (aRKe9.getUTCMilli" ascii
    $s3  = ").toString(10) == \"20\") {var aTEb1 = aZn8[\"split\"](\"`\"); return aTEb1.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`1`+`1`=`3`d`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`)`2`i`M`a`(`9`k`C`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`1`b`E`T`a` `n`r`u`t`e`r`;`}`;`)`0`d`D`M`a`(`]`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`)`\\x22`i`s`j`p`z`x`q`5`x`/`m`o`c`.`g`n`o`r`n`a`w`z`s`\\x2" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`5`a`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`o`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`o`U`a`;`)`2` `,`1`m`B`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`0` `=` `1`l`R`V`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `7`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`1`+`1`=`3`d`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`)`2`i`M`a`(`9`k`C`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`v`C`a`=`6`c`B`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"}`;`h`t`a`P`t`r`o`h`S`.`6`d`K`Q`a` `n`r`u`t`e`r`;`)`6`c`B`a`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\"/`*`@` `}`;`8`n`Z`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYf2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}