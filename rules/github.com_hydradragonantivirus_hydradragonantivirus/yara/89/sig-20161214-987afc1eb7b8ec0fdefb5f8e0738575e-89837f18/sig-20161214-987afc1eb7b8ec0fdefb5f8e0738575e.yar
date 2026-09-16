rule sig_20161214_987afc1eb7b8ec0fdefb5f8e0738575e {
  meta:
    description = "datamaliciousorder - file 20161214_987afc1eb7b8ec0fdefb5f8e0738575e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "660f140d9ac92fae00b649ec4d7b30d3f04455f5ea80b88be7fe7cbefe05fd2c"

  strings:
    $s1  = "function aBWf4(aGn5) {eval(\"/*@cc_on var aUDb7 = new Date() @*/\");aUDb7[\"setUTCSeconds\"](\"0\", \"20\");if (aUDb7.getUTCMill" ascii
    $s2  = "function aBWf4(aGn5) {eval(\"/*@cc_on var aUDb7 = new Date() @*/\");aUDb7[\"setUTCSeconds\"](\"0\", \"20\");if (aUDb7.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`5`n`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`7`v`Z`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`5`a" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`8`x`D`S`a` `n`r`u`t`e`r`;`}`;`)`8`e`N`a`(`]`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`)`3`v`C`a`(`6`c`Z`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`5`x`V`a`;`)`2` `,`9`h`W`H`a`(`]" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`1`+`1`=`9`a`Q`I`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`0` `=` `8`d`J`O`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"}`;`h`t`a`P`t`r`o`h`S`.`7`l`N`a` `n`r`u`t`e`r`;`)`2`g`L`A`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBWf4(\"/`*`@` `}`;`8`x`D`S`a` `n`r`u`t`e`r`;`}`;`)`8`e`N`a`(`]`\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}