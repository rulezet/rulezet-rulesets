rule sig_20161215_672aa3faa913249638f4d9bac253ab2b {
  meta:
    description = "datamaliciousorder - file 20161215_672aa3faa913249638f4d9bac253ab2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fa03406a509fd8ca6b40ba07c19c2dd31c4ec494b997973f830c93d0a3e2c40"

  strings:
    $s1  = "function aOm9(aRo7) {eval(\"/*@cc_on var aQz6 = new Date() @*/\");aQz6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQz6[\"getUTCM" ascii
    $s2  = "function aOm9(aRo7) {eval(\"/*@cc_on var aQz6 = new Date() @*/\");aQz6[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQz6[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `9`l`L`a` `r`a`v` ` ` ` \")), 1" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\"/`*`@` `}`;`2`t`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`a`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`1`y`X`C`a`;`)`2` `,`9`b`H`a`(`]`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`0`a`B`a` `+` `6`l`M`P`a`=`2`w`S`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`)`\\x22`x`i`1`5`x`c`y`u`/`m`o`c`.`e`l`b`u`o`d`n`i`a`r`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`1`+`1`=`3`d`Y`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`)`\\x22`g`r`f`q`w`x`k`p`/`m`o`c`.`s`b`e`w`0`5`.`k`o`o`b`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`w`S`a`=`6`z`Y`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`0` `=` `4`y`Q`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\"/`*`@` `}`;`2`d`K`X`a` `n`r`u`t`e`r`;`}`;`)`7`m`K`W`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`1`+`1`=`3`d`Y`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aOm9(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`m`G`X`a` `r`a`v` `;`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}