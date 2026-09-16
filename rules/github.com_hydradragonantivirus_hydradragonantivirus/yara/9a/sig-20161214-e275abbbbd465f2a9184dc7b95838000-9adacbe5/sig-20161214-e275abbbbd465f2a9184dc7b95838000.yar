rule sig_20161214_e275abbbbd465f2a9184dc7b95838000 {
  meta:
    description = "datamaliciousorder - file 20161214_e275abbbbd465f2a9184dc7b95838000.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0a0df6fef2f213251522b3b626e331784ed810a8e53871b4aacec92414572be"

  strings:
    $s1  = "function aMKq3(aHn0) {eval(\"/*@cc_on var aBXw7 = new Date() @*/\");aBXw7[\"setUTCSeconds\"](\"0\", \"20\");if (aBXw7.getUTCMill" ascii
    $s2  = "function aMKq3(aHn0) {eval(\"/*@cc_on var aBXw7 = new Date() @*/\");aBXw7[\"setUTCSeconds\"](\"0\", \"20\");if (aBXw7.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`1`+`1`=`7`z`N`T`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"/`*`@` `}`;`0`l`U`N`a` `n`r`u`t`e`r`;`}`;`)`8`n`Q`a`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`8`u`G`a` `+` `5`x`O`a`=`0`x`N`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"/`*`@` `}`;`0`n`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"\")), 1);" fullword ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`f`s`a`j`v`d`6`/`m`o`c`.`h`n`i`d`y`m`e`m`o`h`n`i`v" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"/`*`@` `}`;`0`l`U`N`a` `n`r`u`t`e`r`;`}`;`)`8`n`Q`a`(`]`\\x" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`x`N`a`=`8`m`R" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`f`g`s`i`n`b`7`/`z`c`.`k`a`l`m`u`h`.`4`6`n`a`m`o`r" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"/`*`@` `}`;`5`i`N`C`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`x`N`a`=`8`m`R" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\"/`*`@` `}`;`)`4`c`B`a`(`6`r`X`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aMKq3(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}