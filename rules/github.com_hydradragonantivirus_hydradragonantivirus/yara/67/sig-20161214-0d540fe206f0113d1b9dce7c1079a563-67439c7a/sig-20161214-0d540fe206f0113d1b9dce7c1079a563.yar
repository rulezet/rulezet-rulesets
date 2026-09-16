rule sig_20161214_0d540fe206f0113d1b9dce7c1079a563 {
  meta:
    description = "datamaliciousorder - file 20161214_0d540fe206f0113d1b9dce7c1079a563.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8ac01c5bc8d6f8faa34c64a8f71be925ede70d38569481686a96eebe3f52765"

  strings:
    $s1  = "function aLa1(aEEu6) {eval(\"/*@cc_on var aXVu3 = new Date() @*/\");aXVu3[\"setUTCSeconds\"](\"0\", \"20\");if (aXVu3.getUTCMill" ascii
    $s2  = "function aLa1(aEEu6) {eval(\"/*@cc_on var aXVu3 = new Date() @*/\");aXVu3[\"setUTCSeconds\"](\"0\", \"20\");if (aXVu3.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`)`5`p`N`a`(`2`p`V`G`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s6  = "().toString(10) == \"20\") {var aFx8 = aEEu6[\"split\"](\"`\"); return aFx8.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`j`H`D`a`;`)`2` `,`8`a`Z`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`6`u`T`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`6`u`T`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`8`x`F`a` `n`r`u`t`e`r`;`}`;`)`7`f`H`a`(`]`\\x22`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"/`*`@` `}`;`6`u`E`E`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"}`;`h`t`a`P`t`r`o`h`S`.`1`a`I`a` `n`r`u`t`e`r`;`)`3`d`D`C`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`1`o`J`J`a` `+` `3`j`M`T`a`=`8`z`G`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\"}`;`h`t`a`P`t`r`o`h`S`.`1`a`I`a` `n`r`u`t`e`r`;`)`3`d`D`C`a`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `1`j`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`1`+`1`=`1`s`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aLa1(\";`1`+`1`=`1`s`L`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}