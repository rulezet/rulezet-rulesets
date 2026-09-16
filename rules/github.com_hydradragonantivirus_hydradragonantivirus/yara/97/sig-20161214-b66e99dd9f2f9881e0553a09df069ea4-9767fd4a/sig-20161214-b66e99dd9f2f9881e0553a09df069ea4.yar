rule sig_20161214_b66e99dd9f2f9881e0553a09df069ea4 {
  meta:
    description = "datamaliciousorder - file 20161214_b66e99dd9f2f9881e0553a09df069ea4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3da62557a0676e385b6471aee9f1297c093b569d916a1ac7643bb7c2258d0489"

  strings:
    $s1  = "function aYFp3(aPNl3) {eval(\"/*@cc_on var aHg5 = new Date() @*/\");aHg5[\"setUTCSeconds\"](\"0\", \"20\");if (aHg5.getUTCMillis" ascii
    $s2  = "function aYFp3(aPNl3) {eval(\"/*@cc_on var aHg5 = new Date() @*/\");aHg5[\"setUTCSeconds\"](\"0\", \"20\");if (aHg5.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`a`M`B`a`;`)`2` `,`2`n`M`a`(`]" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`)`9`l`I`R`a`(`0`q`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s7  = ".toString(10) == \"20\") {var aPSc9 = aPNl3[\"split\"](\"`\"); return aPSc9.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`9`c`S`P`a` `n`r`u`t`e`r`;`}`;`)`9`y`Z`C`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`6`b`V`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`1`+`1`=`8`n`H`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`)`9`l`I`R`a`(`0`q`W`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"}`;`h`t`a`P`t`r`o`h`S`.`3`a`Q`a` `n`r`u`t`e`r`;`)`3`e`A`a`(" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYFp3(\"/`*`@` `}`;`3`l`N`P`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}