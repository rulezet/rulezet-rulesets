rule sig_20161214_2ec79939016b11dd64bec4903bb2c665 {
  meta:
    description = "datamaliciousorder - file 20161214_2ec79939016b11dd64bec4903bb2c665.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9586304c4d12a29d4bde7fd43a9c7937457c8393458948a7da6c6074e760e73"

  strings:
    $s1  = "function aUx2(aTPl3) {eval(\"/*@cc_on var aSj2 = new Date() @*/\");aSj2[\"setUTCSeconds\"](\"0\", \"20\");if (aSj2.getUTCMillise" ascii
    $s2  = "function aUx2(aTPl3) {eval(\"/*@cc_on var aSj2 = new Date() @*/\");aSj2[\"setUTCSeconds\"](\"0\", \"20\");if (aSj2.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"/`*`@` `}`;`9`r`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`c`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"/`*`@` `}`;`)`0`p`G`a`(`9`e`E`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"/`*`@` `}`;`)`0`p`G`a`(`9`e`E`W`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`1`+`1`=`3`i`S`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`l`F`a` `n`r`u`t`e`r`;`)`6`d`L`S`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"/`*`@` `}`;`3`l`P`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`l`F`a` `n`r`u`t`e`r`;`)`6`d`L`S`a`" ascii
    $s15 = "toString(10) == \"20\") {var aDBf0 = aTPl3[\"split\"](\"`\"); return aDBf0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`a`G`L`a`;`)`2` `,`0`t`S`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`0`8`v`i`r`u`g`j`m`/`m`o`c`.`s`y`b`u`s`\\x22` `+` `" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUx2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}