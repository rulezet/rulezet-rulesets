rule sig_20161214_26dd5d61570a672af6b5a23ec412da50 {
  meta:
    description = "datamaliciousorder - file 20161214_26dd5d61570a672af6b5a23ec412da50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d57dad4ebf5a5c819c3f8de6d68bdeda53b4f31f9ee4e51934088f72887d07"

  strings:
    $s1  = "function aTMi0(aOZl4) {eval(\"/*@cc_on var aMa9 = new Date() @*/\");aMa9[\"setUTCSeconds\"](\"0\", \"20\");if (aMa9.getUTCMillis" ascii
    $s2  = "function aTMi0(aOZl4) {eval(\"/*@cc_on var aMa9 = new Date() @*/\");aMa9[\"setUTCSeconds\"](\"0\", \"20\");if (aMa9.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`q`g`q`k`9`h`/`m`o`c`.`t`n`e`r`b`r`o`f`\\x22` `+` " ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\"/`*`@` `}`;`)`1`u`Z`a`(`3`v`E`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`t`N`a`=`1`i`I" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`k`Y`a` `r`a`v` ` ` ` \")), " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`6`h`I`X`a` `+` `6`u`S`C`a`=`4`t`N`a` `r`a`v\")), 1);" fullword ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\"/`*`@` `}`;`4`l`Z`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s14 = ".toString(10) == \"20\") {var aXPz0 = aOZl4[\"split\"](\"`\"); return aXPz0.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`z`P`W`a` `n`r`u`t`e`r`;`)`1`i`I`L" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\"/`*`@` `}`;`6`r`F`H`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`8`7`z`7`i`/`m`o`c`.`y`k`c`u`t`n`e`k`.`e`n`i`l`n`o" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`)`\\x22`s`u`y`e`h`/`t`e`n`.`g`n`o`l`t`e`i`r`t`\\x22` `+` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTMi0(\";`1`+`1`=`0`a`F`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}