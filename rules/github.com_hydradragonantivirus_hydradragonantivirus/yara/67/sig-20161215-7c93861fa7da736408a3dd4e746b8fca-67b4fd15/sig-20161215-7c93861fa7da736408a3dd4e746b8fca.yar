rule sig_20161215_7c93861fa7da736408a3dd4e746b8fca {
  meta:
    description = "datamaliciousorder - file 20161215_7c93861fa7da736408a3dd4e746b8fca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11fec1c7f249ffec75f178a1fbffdeedcce0c52e63178feb737a5e4741feb516"

  strings:
    $s1  = "function aOLj5(aYh7) {eval(\"/*@cc_on var aGZt7 = new Date() @*/\");aGZt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGZt7[\"get" ascii
    $s2  = "function aOLj5(aYh7) {eval(\"/*@cc_on var aGZt7 = new Date() @*/\");aGZt7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGZt7[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`j`W`a` `n`r`u`t`e`r`;`)`1`y`W`a`(" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`1`+`1`=`8`m`O`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`p`Q`Z`a`;`)`2` `,`7`o`M`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`u`t`j`i`d`g`s`/`m`o`c`.`b`o`j`l`e`g`n`a`.`w`w`w`" ascii
    $s7  = "onds\"]()[\"toString\"](10) == \"20\") {var aAg6 = aYh7[\"split\"](\"`\"); return aAg6[\"reverse\"]().join(\"\");} else return " ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`p`Q`Z`a`;`)`2` `,`7`o`M`a`(`]" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`j`W`a` `n`r`u`t`e`r`;`)`1`y`W`a`(" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`1`+`1`=`8`m`O`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`5`r`I`C`a` `+` `2`a`Q`a`=`3`u`N`a` `r`a`v\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`u`N`a`=`1`y`W" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOLj5(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `7`h`G`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}