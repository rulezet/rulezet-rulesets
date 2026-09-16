rule sig_20161215_24267f1c5aab786f6f9ac8bad2b127cc {
  meta:
    description = "datamaliciousorder - file 20161215_24267f1c5aab786f6f9ac8bad2b127cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "243bf7eaefc5a703815a81ac6a5274076f612942988d16278cb4803ba327e9a7"

  strings:
    $s1  = "function aCc8(aCu9) {eval(\"/*@cc_on var aLPm5 = new Date() @*/\");aLPm5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLPm5[\"getU" ascii
    $s2  = "function aCc8(aCu9) {eval(\"/*@cc_on var aLPm5 = new Date() @*/\");aLPm5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLPm5[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`d`O`G`a`;`)`2` `,`6`a`Y`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`g`Z`a` `r`a`v` `;`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`0` `=` `0`u`F`B`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`j`X`M`a`=`1`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`\\x22`c`j`w`v`q`/`m`o`c`.`d`r`o`c`e`r`e`e`r`t`g`i`b`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`1`+`1`=`2`t`U`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`d`O`G`a`;`)`2` `,`6`a`Y`a`(`]`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`(`y`a`r`r`A` `w`e`n` `=` `1`u`B`a` `r`a`v` ` ` ` \")), 1" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`g`Z`a` `r`a`v` `;`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`1`+`1`=`2`t`U`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\"/`*`@` `}`;`9`u`C`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "nds\"]()[\"toString\"](10) == \"20\") {var aVj2 = aCu9[\"split\"](\"`\"); return aVj2[\"reverse\"]().join(\"\");} else return \"" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aCc8(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}