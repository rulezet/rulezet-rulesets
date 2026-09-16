rule sig_20161215_4148fab5aeca9190e0a9f5bb3804b949 {
  meta:
    description = "datamaliciousorder - file 20161215_4148fab5aeca9190e0a9f5bb3804b949.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed569ea91fe88a5b9f2ef2d64575f1275e6d249720db7fbacd4294d22587ce95"

  strings:
    $s1  = "function aYMm6(aGVh2) {eval(\"/*@cc_on var aIDs8 = new Date() @*/\");aIDs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIDs8[\"ge" ascii
    $s2  = "function aYMm6(aGVh2) {eval(\"/*@cc_on var aIDs8 = new Date() @*/\");aIDs8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aIDs8[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`3`p`3`p`s`0`w`q`q`y`/`m`o`c`.`a`n`i`m`u`l`a`-`o`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`1`f`O`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`a`T`a`;`)`2` `,`6`j`M`G`a`(`]" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`7`v`E`a` `n`r`u`t`e`r`;`}`;`)`0`v`R`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"}`;`h`t`a`P`t`r`o`h`S`.`6`x`K`a` `n`r`u`t`e`r`;`)`9`x`N`O`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`2`h`V`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`)`6`p`Q`a`(`7`i`B`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`q`J`a` `r`a`v` `;`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\"/`*`@` `}`;`2`h`V`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `5" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `0`q`J`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aYMm6(\";`)`\\x22`l`t`t`s`x`/`m`o`c`.`e`u`y`i`a`u`h`c`\\x22` `+` `5" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}