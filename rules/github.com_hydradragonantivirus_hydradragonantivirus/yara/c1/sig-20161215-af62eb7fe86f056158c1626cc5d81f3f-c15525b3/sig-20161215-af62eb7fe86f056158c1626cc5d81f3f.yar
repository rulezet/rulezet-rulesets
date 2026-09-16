rule sig_20161215_af62eb7fe86f056158c1626cc5d81f3f {
  meta:
    description = "datamaliciousorder - file 20161215_af62eb7fe86f056158c1626cc5d81f3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea590ce5a1151b058120cf334945d8fe2ab383319cd307462000b47a4802b22d"

  strings:
    $s1  = "function aADc6(aNa9) {eval(\"/*@cc_on var aGf0 = new Date() @*/\");aGf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGf0[\"getUTC" ascii
    $s2  = "function aADc6(aNa9) {eval(\"/*@cc_on var aGf0 = new Date() @*/\");aGf0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aGf0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"/`*`@` `}`;`5`v`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`a" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`l`X`a`=`1`z`I" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"/`*`@` `}`;`9`a`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`j`f`m`7`6`/`r`b`.`m`o`c`.`o`c`o`l`a`b`o`\\x22` `+" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"\")), 1);" fullword ascii
    $s12 = "s\"]()[\"toString\"](10) == \"20\") {var aPIt5 = aNa9[\"split\"](\"`\"); return aPIt5[\"reverse\"]().join(\"\");} else return \"" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"}`;`h`t`a`P`t`r`o`h`S`.`2`k`Y`a` `n`r`u`t`e`r`;`)`1`z`I`T`a" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`s`c`f`r`y`r`/`m`o`c`.`d`n`a`l`d`o`o`g`o`i`b`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` " ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`e`n`p`6`2`z`0`n`f`/`m`o`c`.`e`c`n`a`r`u`s`n`i`e`c" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\";`)`\\x22`6`o`c`e`k`u`7`d`6`/`t`e`n`.`s`n`a`l`p`t`a`o`b`y`m" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aADc6(\"/`*`@` `}`;`9`a`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}