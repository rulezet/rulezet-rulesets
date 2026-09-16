rule sig_20161215_1a569aaf715041799a82fe9e02616ec3 {
  meta:
    description = "datamaliciousorder - file 20161215_1a569aaf715041799a82fe9e02616ec3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b889e12ddd2a5c6fcc8e3d4da12fb8c74ec9ef3f6efcdd436998db1f86c8f51d"

  strings:
    $s1  = "function aJBw6(aGy6) {eval(\"/*@cc_on var aHs0 = new Date() @*/\");aHs0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHs0[\"getUTC" ascii
    $s2  = "function aJBw6(aGy6) {eval(\"/*@cc_on var aHs0 = new Date() @*/\");aHs0[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aHs0[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`0` `=` `6`s`J`V`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\"/`*`@` `}`;`1`e`V`a` `n`r`u`t`e`r`;`}`;`)`3`e`S`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\"/`*`@` `}`;`6`y`G`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`1`+`1`=`2`v`Y`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`b`m`s`j`j`/`u`e`.`o`b`o`l`g`l`e`t`o`h`\\x22` `+` " ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\"/`*`@` `}`;`1`e`V`a` `n`r`u`t`e`r`;`}`;`)`3`e`S`a`(`]`\\x22" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `9`w`H`P`a` `r`a`v` `;" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`1`+`1`=`2`v`Y`Y`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\"}`;`h`t`a`P`t`r`o`h`S`.`7`s`K`a` `n`r`u`t`e`r`;`)`6`d`N`H`a" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJBw6(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}