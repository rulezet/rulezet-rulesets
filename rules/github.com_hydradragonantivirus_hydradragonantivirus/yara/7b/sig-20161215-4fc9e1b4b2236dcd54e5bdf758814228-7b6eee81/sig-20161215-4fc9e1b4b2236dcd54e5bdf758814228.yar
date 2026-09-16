rule sig_20161215_4fc9e1b4b2236dcd54e5bdf758814228 {
  meta:
    description = "datamaliciousorder - file 20161215_4fc9e1b4b2236dcd54e5bdf758814228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7302ca3b11ca00e1152f05bbbc03f15bae14238d4bae0d8624ef3e37af060e2a"

  strings:
    $s1  = "function aXTo9(aBHu9) {eval(\"/*@cc_on var aHu7 = new Date() @*/\");aHu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHu7[\"getUT" ascii
    $s2  = "function aXTo9(aBHu9) {eval(\"/*@cc_on var aHu7 = new Date() @*/\");aHu7[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHu7[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `0`w`Y`N`a` `r`a`v` ` ` ` \"))" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`e`K`a`=`0`d`X" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`9`u`H`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`i`O`a` `n`r`u`t`e`r`;`)`0`d`X`V`a" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`)`4`q`C`a`(`7`g`E`S`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`a`S`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`u`Z`Q`a`;`)`2` `,`4`c`Z`a`(`]" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`4`o`Y`U`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`9`e`K`a` `n`r`u`t`e`r`;`}`;`)`3`q`A`a`(`]`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`)`\\x22`k`p`i`p`n`o`y`8`9`q`/`n`c`.`c`i`m`2`7`\\x22` `+` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`0` `=` `6`z`L`N`a` `r`a`v\")), 1);" fullword ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aXTo9(\"/`*`@` `}`;`9`u`H`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}