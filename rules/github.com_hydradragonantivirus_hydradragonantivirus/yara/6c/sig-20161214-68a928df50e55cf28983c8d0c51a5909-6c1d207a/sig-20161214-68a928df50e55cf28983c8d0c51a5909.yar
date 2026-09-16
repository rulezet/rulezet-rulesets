rule sig_20161214_68a928df50e55cf28983c8d0c51a5909 {
  meta:
    description = "datamaliciousorder - file 20161214_68a928df50e55cf28983c8d0c51a5909.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f337d06d47d852a7d2ca4d4bc7e414d7cd87a86edc01439a5b249bcb89a50cc"

  strings:
    $s1  = "function aNa7(aIHo3) {eval(\"/*@cc_on var aURx0 = new Date() @*/\");aURx0[\"setUTCSeconds\"](\"0\", \"20\");if (aURx0.getUTCMill" ascii
    $s2  = "function aNa7(aIHo3) {eval(\"/*@cc_on var aURx0 = new Date() @*/\");aURx0[\"setUTCSeconds\"](\"0\", \"20\");if (aURx0.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`1`+`1`=`1`t`U`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`0` `=` `1`n`P`N`a` `r`a`v\")), 1);" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"/`*`@` `}`;`)`0`e`F`a`(`5`v`C`F`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`r`F`a`=`5`f`G`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"/`*`@` `}`;`9`d`E`S`a` `n`r`u`t`e`r`;`}`;`)`3`b`G`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`r`F`a`=`5`f`G`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"}`;`h`t`a`P`t`r`o`h`S`.`2`o`F`A`a` `n`r`u`t`e`r`;`)`5`f`G`G`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"/`*`@` `}`;`9`d`E`S`a` `n`r`u`t`e`r`;`}`;`)`3`b`G`a`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\"/`*`@` `}`;`3`o`H`I`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s17 = "().toString(10) == \"20\") {var aSEd9 = aIHo3[\"split\"](\"`\"); return aSEd9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aNa7(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}