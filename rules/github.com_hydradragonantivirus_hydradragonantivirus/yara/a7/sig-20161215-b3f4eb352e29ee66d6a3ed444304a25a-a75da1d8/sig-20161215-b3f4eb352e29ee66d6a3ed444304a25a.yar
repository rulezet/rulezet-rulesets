rule sig_20161215_b3f4eb352e29ee66d6a3ed444304a25a {
  meta:
    description = "datamaliciousorder - file 20161215_b3f4eb352e29ee66d6a3ed444304a25a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdd3821b69f4b2c35943c02f8254fa2c0d1171d6e3b2c541a028921da7679a5f"

  strings:
    $s1  = "function aVLb0(aYJa1) {eval(\"/*@cc_on var aQa2 = new Date() @*/\");aQa2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQa2[\"getUT" ascii
    $s2  = "function aVLb0(aYJa1) {eval(\"/*@cc_on var aQa2 = new Date() @*/\");aQa2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQa2[\"getUT" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`m`o`c`.`e`k`a`w`n`a`c`i`r`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`1`+`1`=`3`w`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"/`*`@` `}`;`)`3`z`J`R`a`(`3`v`U`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`k`M`Z`a` `n`r`u`t`e`r`;`)`6`g`U`M" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"/`*`@` `}`;`0`w`C`a` `n`r`u`t`e`r`;`}`;`)`4`w`I`H`a`(`]`\\x" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`)`\\x22`l`m`n`5`n`6`q`/`m`o`c`.`i`h`s`u`o`b`a`m`a`y`o`n`o" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"}`;`h`t`a`P`t`r`o`h`S`.`5`k`M`Z`a` `n`r`u`t`e`r`;`)`6`g`U`M" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`1`+`1`=`3`w`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s16 = "ds\"]()[\"toString\"](10) == \"20\") {var aCw0 = aYJa1[\"split\"](\"`\"); return aCw0[\"reverse\"]().join(\"\");} else return \"" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"/`*`@` `}`;`1`a`J`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`e`H`S`a`;`)`2` `,`5`x`B`a`(`]" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\"/`*`@` `}`;`0`w`C`a` `n`r`u`t`e`r`;`}`;`)`4`w`I`H`a`(`]`\\x" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVLb0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `3`z`P`a`=`6`g`U" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}