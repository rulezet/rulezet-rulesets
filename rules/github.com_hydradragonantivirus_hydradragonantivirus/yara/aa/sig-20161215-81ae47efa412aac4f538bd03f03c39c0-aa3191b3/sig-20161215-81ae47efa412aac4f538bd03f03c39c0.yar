rule sig_20161215_81ae47efa412aac4f538bd03f03c39c0 {
  meta:
    description = "datamaliciousorder - file 20161215_81ae47efa412aac4f538bd03f03c39c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62689ca35dfd3559fc0b4907f2dda07639e808f5f313b3b34f3096717d371a91"

  strings:
    $s1  = "function aTGl3(aQSd4) {eval(\"/*@cc_on var aQQg0 = new Date() @*/\");aQQg0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQQg0[\"ge" ascii
    $s2  = "function aTGl3(aQSd4) {eval(\"/*@cc_on var aQQg0 = new Date() @*/\");aQQg0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQQg0[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"}`;`h`t`a`P`t`r`o`h`S`.`8`r`S`S`a` `n`r`u`t`e`r`;`)`5`u`M`E" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`d`Z`Q`a` `r`a`v` `;" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`4`d`S`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s6  = "conds\"]()[\"toString\"](10) == \"20\") {var aKQl8 = aQSd4[\"split\"](\"`\"); return aKQl8[\"reverse\"]().join(\"\");} else retu" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`9`j`D`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `6`v`Z" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` " ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`1`+`1`=`1`p`A`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`8`l`Q`K`a` `n`r`u`t`e`r`;`}`;`)`7`s`O`a`(`]`\\x" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`)`9`j`X`a`(`9`w`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`z`M`R`a`=`5`u" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aTGl3(\"/`*`@` `}`;`9`j`D`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}