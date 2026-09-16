rule sig_20161214_e804105a4fccc0e2a7f9477c79657686 {
  meta:
    description = "datamaliciousorder - file 20161214_e804105a4fccc0e2a7f9477c79657686.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b018d461fd5818c8ca2885704b717f9c8379687f88de94a232614fdf5a21949a"

  strings:
    $s1  = "function aZs9(aUe2) {eval(\"/*@cc_on var aAn0 = new Date() @*/\");aAn0[\"setUTCSeconds\"](\"0\", \"20\");if (aAn0.getUTCMillisec" ascii
    $s2  = "function aZs9(aUe2) {eval(\"/*@cc_on var aAn0 = new Date() @*/\");aAn0[\"setUTCSeconds\"](\"0\", \"20\");if (aAn0.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"/`*`@` `}`;`2`e`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`0` `=` `1`i`K`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"/`*`@` `}`;`2`e`U`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`e`H`C`a` `n`r`u`t`e`r`;`)`2`n`E`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"/`*`@` `}`;`3`y`K`K`a` `n`r`u`t`e`r`;`}`;`)`7`e`K`a`(`]`\\x2" ascii
    $s14 = "oString(10) == \"20\") {var aKKy3 = aUe2[\"split\"](\"`\"); return aKKy3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"}`;`h`t`a`P`t`r`o`h`S`.`7`e`H`C`a` `n`r`u`t`e`r`;`)`2`n`E`a`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`i`A`a`;`)`2` `,`6`i`O`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aZs9(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}