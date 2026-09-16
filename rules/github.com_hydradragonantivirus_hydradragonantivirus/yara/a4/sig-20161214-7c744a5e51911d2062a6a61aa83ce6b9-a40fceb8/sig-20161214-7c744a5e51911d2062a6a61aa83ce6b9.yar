rule sig_20161214_7c744a5e51911d2062a6a61aa83ce6b9 {
  meta:
    description = "datamaliciousorder - file 20161214_7c744a5e51911d2062a6a61aa83ce6b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0272bfeb4be1e57df51805d65b869557ebcc86a08e9248d66a4408055c1063b4"

  strings:
    $s1  = "function aWx5(aQg9) {eval(\"/*@cc_on var aOp0 = new Date() @*/\");aOp0[\"setUTCSeconds\"](\"0\", \"20\");if (aOp0.getUTCMillisec" ascii
    $s2  = "function aWx5(aQg9) {eval(\"/*@cc_on var aOp0 = new Date() @*/\");aOp0[\"setUTCSeconds\"](\"0\", \"20\");if (aOp0.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`e`I`a`=`8`z`A`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "oString(10) == \"20\") {var aTAw3 = aQg9[\"split\"](\"`\"); return aTAw3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`1`+`1`=`2`y`F`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\"/`*`@` `}`;`3`w`A`T`a` `n`r`u`t`e`r`;`}`;`)`8`c`B`P`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\"/`*`@` `}`;`9`g`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`k`Z`a`;`)`2` `,`4`d`S`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`k`Z`a`;`)`2` `,`4`d`S`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`d`w`n`h`3`c`m`/`m`o`c`.`i`a`i`d`u`w`\\x22` `+` `2`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWx5(\";`)`\\x22`v`h`m`q`6`h`a`a`/`r`t`.`m`o`c`.`s`d`r`o`w`d`d`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}