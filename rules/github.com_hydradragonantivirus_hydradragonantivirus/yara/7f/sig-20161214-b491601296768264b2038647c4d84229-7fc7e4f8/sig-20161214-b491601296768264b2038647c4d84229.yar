rule sig_20161214_b491601296768264b2038647c4d84229 {
  meta:
    description = "datamaliciousorder - file 20161214_b491601296768264b2038647c4d84229.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb7246536c1cec51f33cb3b5708476a933bf34ca56663b26ad5b57031c2cf8f"

  strings:
    $s1  = "function aFt1(aWIh5) {eval(\"/*@cc_on var aEi1 = new Date() @*/\");aEi1[\"setUTCSeconds\"](\"0\", \"20\");if (aEi1.getUTCMillise" ascii
    $s2  = "function aFt1(aWIh5) {eval(\"/*@cc_on var aEi1 = new Date() @*/\");aEi1[\"setUTCSeconds\"](\"0\", \"20\");if (aEi1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`p`z`e`5`i`q`p`q`5`/`h`c`.`t`e`r`u`d`e`n`i`r`e`h`t`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`6`t`S`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`6`t`S`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`5`h`I`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`x`N`R`a`;`)`2` `,`0`m`X`V`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`5`h`I`W`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s16 = "toString(10) == \"20\") {var aIr2 = aWIh5[\"split\"](\"`\"); return aIr2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"}`;`h`t`a`P`t`r`o`h`S`.`7`z`A`B`a` `n`r`u`t`e`r`;`)`2`f`M`a`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFt1(\"/`*`@` `}`;`2`r`I`a` `n`r`u`t`e`r`;`}`;`)`8`c`P`a`(`]`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}