rule sig_20161214_b8bf153b12fca89866ebcfd4ba3b1f66 {
  meta:
    description = "datamaliciousorder - file 20161214_b8bf153b12fca89866ebcfd4ba3b1f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37c080758bcb8c871d0768520d3bf4590d00f5f21758d9de902a8041e4678a1f"

  strings:
    $s1  = "function aHJu3(aKMy7) {eval(\"/*@cc_on var aAh9 = new Date() @*/\");aAh9[\"setUTCSeconds\"](\"0\", \"20\");if (aAh9.getUTCMillis" ascii
    $s2  = "function aHJu3(aKMy7) {eval(\"/*@cc_on var aAh9 = new Date() @*/\");aAh9[\"setUTCSeconds\"](\"0\", \"20\");if (aAh9.getUTCMillis" ascii
    $s3  = ".toString(10) == \"20\") {var aDCb0 = aKMy7[\"split\"](\"`\"); return aDCb0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"/`*`@` `}`;`8`c`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`z" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"/`*`@` `}`;`0`b`C`D`a` `n`r`u`t`e`r`;`}`;`)`2`q`L`I`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`3`5`3`6`s`q`y`w`/`m`o`c`.`i`c`r`a`c`s`i`v`\\x22` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`6`t`q`q`x`d`s`u`/`t`e`n`.`s`u`b`c`u`\\x22` `+` `6" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"}`;`h`t`a`P`t`r`o`h`S`.`4`j`P`a` `n`r`u`t`e`r`;`)`1`t`P`a`(" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"/`*`@` `}`;`0`b`C`D`a` `n`r`u`t`e`r`;`}`;`)`2`q`L`I`a`(`]`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\"/`*`@` `}`;`)`7`q`H`C`a`(`2`f`P`S`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`a`U`a`=`1`t`P" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aHJu3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}