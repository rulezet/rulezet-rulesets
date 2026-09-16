rule sig_20161214_179f3cbc9ef491b3e24afab9a85bdb63 {
  meta:
    description = "datamaliciousorder - file 20161214_179f3cbc9ef491b3e24afab9a85bdb63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1aa3e0b442a31e73722ce580445398701f3e5655fe6a7ea8a6791a7179efceca"

  strings:
    $s1  = "function aXMw0(aNm1) {eval(\"/*@cc_on var aJg0 = new Date() @*/\");aJg0[\"setUTCSeconds\"](\"0\", \"20\");if (aJg0.getUTCMillise" ascii
    $s2  = "function aXMw0(aNm1) {eval(\"/*@cc_on var aJg0 = new Date() @*/\");aJg0[\"setUTCSeconds\"](\"0\", \"20\");if (aJg0.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`1`m`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`6`r`F`a` `n`r`u`t`e`r`;`}`;`)`3`p`C`R`a`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`p`H`H`a`;`)`2` `,`2`y`R`K`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`\\x22`s`x`t`r`w`o`i`l`/`t`p`.`k`a`e`p`s`u`o`y`\\x22` `+" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`p`H`H`a`;`)`2` `,`2`y`R`K`a`(" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"}`;`h`t`a`P`t`r`o`h`S`.`2`z`Z`N`a` `n`r`u`t`e`r`;`)`5`b`Z`a" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`\\x22`e`k`s`9`j`6`g`j`m`k`/`m`o`c`.`n`o`w`i`n`-`u`\\x22" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`6`r`F`a` `n`r`u`t`e`r`;`}`;`)`3`p`C`R`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`1`+`1`=`8`i`S`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`1`m`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s18 = "toString(10) == \"20\") {var aFr6 = aNm1[\"split\"](\"`\"); return aFr6.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXMw0(\"/`*`@` `}`;`)`2`a`I`a`(`7`x`Q`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}