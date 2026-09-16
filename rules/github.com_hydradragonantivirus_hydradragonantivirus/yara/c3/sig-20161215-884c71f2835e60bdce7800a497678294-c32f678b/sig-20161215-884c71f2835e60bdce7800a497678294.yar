rule sig_20161215_884c71f2835e60bdce7800a497678294 {
  meta:
    description = "datamaliciousorder - file 20161215_884c71f2835e60bdce7800a497678294.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51aa6712aeb9c1b0a99ad4f83aded774a821a9c8b4a0a76c25bf7f828f084f06"

  strings:
    $s1  = "function aGNf9(aTHg3) {eval(\"/*@cc_on var aMd5 = new Date() @*/\");aMd5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMd5[\"getUT" ascii
    $s2  = "function aGNf9(aTHg3) {eval(\"/*@cc_on var aMd5 = new Date() @*/\");aMd5[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aMd5[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `1`g`D`N`a`=`4`h" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`1`+`1`=`4`o`O`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"/`*`@` `}`;`9`o`H`I`a` `n`r`u`t`e`r`;`}`;`)`6`f`B`a`(`]`\\x" ascii
    $s8  = "ds\"]()[\"toString\"](10) == \"20\") {var aIHo9 = aTHg3[\"split\"](\"`\"); return aIHo9[\"reverse\"]().join(\"\");} else return " ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"/`*`@` `}`;`3`g`H`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`0`b`S`P`a`;`)`2` `,`9`x`Q`a`(`]" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`0` `=` `7`v`A`I`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`7`g`u`b`g`m`y`c`q`/`m`o`c`.`t`f`o`s`y`l`e`s`i`w`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"}`;`h`t`a`P`t`r`o`h`S`.`2`p`I`L`a` `n`r`u`t`e`r`;`)`4`h`W`A" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"/`*`@` `}`;`2`l`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`u" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\"/`*`@` `}`;`2`l`F`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`9`u" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGNf9(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}