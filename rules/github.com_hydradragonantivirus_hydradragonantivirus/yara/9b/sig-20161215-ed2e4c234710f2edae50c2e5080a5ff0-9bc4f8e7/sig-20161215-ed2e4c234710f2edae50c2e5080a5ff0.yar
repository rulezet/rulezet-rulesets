rule sig_20161215_ed2e4c234710f2edae50c2e5080a5ff0 {
  meta:
    description = "datamaliciousorder - file 20161215_ed2e4c234710f2edae50c2e5080a5ff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c37e5b87485f4553083c026b5b064da9d104240f14a9a5d5a82453ba738087e"

  strings:
    $s1  = "function aSw9(aOc4) {eval(\"/*@cc_on var aLz1 = new Date() @*/\");aLz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLz1[\"getUTCM" ascii
    $s2  = "function aSw9(aOc4) {eval(\"/*@cc_on var aLz1 = new Date() @*/\");aLz1[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLz1[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `8`e`V`D`a` `r`a`v` `;`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`x`K`A`a`=`7`y`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"/`*`@` `}`;`5`n`V`a` `n`r`u`t`e`r`;`}`;`)`8`t`J`a`(`]`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"/`*`@` `}`;`4`c`O`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`s`U`P`a` `n`r`u`t`e`r`;`)`7`y`B`C`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`f`u`g`j`e`/`m`o`c`.`a`w`a`n`i`k`o`-`o`n`i`s`a`c`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `2`o`T`a` `r`a`v` ` ` ` \")), 1" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`)`\\x22`l`n`t`i`u`8`6`/`k`u`.`o`c`.`t`a`a`w`\\x22` `+` `5`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`b`F`P`a`;`)`2` `,`7`l`I`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSw9(\";`0` `=` `7`b`T`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}