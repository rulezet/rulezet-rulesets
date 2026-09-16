rule sig_20161214_31b657b09d51be8d84253f533f0f76ce {
  meta:
    description = "datamaliciousorder - file 20161214_31b657b09d51be8d84253f533f0f76ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6939a448b9bc855f501ca30998dbc20ca3e03752aaa3e6be2db497538e1979fc"

  strings:
    $s1  = "function aWy6(aKw0) {eval(\"/*@cc_on var aGNa0 = new Date() @*/\");aGNa0[\"setUTCSeconds\"](\"0\", \"20\");if (aGNa0.getUTCMilli" ascii
    $s2  = "function aWy6(aKw0) {eval(\"/*@cc_on var aGNa0 = new Date() @*/\");aGNa0[\"setUTCSeconds\"](\"0\", \"20\");if (aGNa0.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x2" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`2`t`N`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`0`w`K`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`m`Y`Y`a`;`)`2` `,`4`v`O`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`m`Y`Y`a`;`)`2` `,`4`v`O`a`(`]`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"\")), 1);" fullword ascii
    $s13 = ").toString(10) == \"20\") {var aAb0 = aKw0[\"split\"](\"`\"); return aAb0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`1`+`1`=`8`p`F`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\"/`*`@` `}`;`)`2`z`J`V`a`(`0`r`K`A`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`1`+`1`=`8`p`F`N`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWy6(\";`)`\\x22`g`d`h`i`y`p`/`n`i`.`t`i`f`o`r`p`e`l`p`o`e`p`\\x22`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}