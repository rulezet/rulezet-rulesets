rule sig_20161215_371d430d3b60948e24ed7c4de3261dae {
  meta:
    description = "datamaliciousorder - file 20161215_371d430d3b60948e24ed7c4de3261dae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0373032ba7b411a9f11e4819fae93dd910e491cd3c0195982243eb1366df763e"

  strings:
    $s1  = "function aBHv9(aGOi0) {eval(\"/*@cc_on var aLMj2 = new Date() @*/\");aLMj2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLMj2[\"ge" ascii
    $s2  = "function aBHv9(aGOi0) {eval(\"/*@cc_on var aLMj2 = new Date() @*/\");aLMj2[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aLMj2[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`1`+`1`=`7`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"/`*`@` `}`;`5`i`S`P`a` `n`r`u`t`e`r`;`}`;`)`9`z`C`a`(`]`\\x" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`K`a`;`)`2` `,`1`u`J`R`a`(`]" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"/`*`@` `}`;`)`6`v`B`F`a`(`2`j`E`N`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`k`T`a`=`7`e`Z" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`c`K`a`;`)`2` `,`1`u`J`R`a`(`]" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `5`u`Y" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`o`M`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `5`o`M`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `6`p`E`a` `r`a`v` ` ` ` \")), " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\"/`*`@` `}`;`6`v`Z`M`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBHv9(\";`1`+`1`=`7`o`G`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}