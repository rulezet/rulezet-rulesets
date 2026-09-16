rule sig_20161215_675e807a701f73d5a6a2384d6555f520 {
  meta:
    description = "datamaliciousorder - file 20161215_675e807a701f73d5a6a2384d6555f520.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2165fbac2ccc5d8c736a0d225e8cb29295af537f6bd345d35e339a07f9866864"

  strings:
    $s1  = "function aBDd0(aBp9) {eval(\"/*@cc_on var aGFd8 = new Date() @*/\");aGFd8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGFd8[\"get" ascii
    $s2  = "function aBDd0(aBp9) {eval(\"/*@cc_on var aGFd8 = new Date() @*/\");aGFd8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGFd8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`9`d`N`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`6`i" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`1`+`1`=`8`m`V`D`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "onds\"]()[\"toString\"](10) == \"20\") {var aAYj6 = aBp9[\"split\"](\"`\"); return aAYj6[\"reverse\"]().join(\"\");} else return" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`6`j`Y`A`a` `n`r`u`t`e`r`;`}`;`)`7`f`O`H`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`9`p`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"\")), 1);" fullword ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"}`;`h`t`a`P`t`r`o`h`S`.`8`e`O`a` `n`r`u`t`e`r`;`)`7`v`K`Y`a" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\"/`*`@` `}`;`6`j`Y`A`a` `n`r`u`t`e`r`;`}`;`)`7`f`O`H`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`)`\\x22`g`v`g`c`c`b`x`q`l`/`n`c`.`t`f`o`s`x`e`l`a`\\x22` " ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBDd0(\";`9`n`G`E`a` `+` `7`x`J`T`a`=`4`y`Z`H`a` `r`a`v\")), 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}