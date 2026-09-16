rule sig_20161214_c78c8ad0a988db08d2f5683d7cf2526b {
  meta:
    description = "datamaliciousorder - file 20161214_c78c8ad0a988db08d2f5683d7cf2526b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "347853266c4b9187de34886f8558d1f95640ba48afd8844a308ad484ebb4e32b"

  strings:
    $s1  = "function aJk3(aHLn6) {eval(\"/*@cc_on var aDh2 = new Date() @*/\");aDh2[\"setUTCSeconds\"](\"0\", \"20\");if (aDh2.getUTCMillise" ascii
    $s2  = "function aJk3(aHLn6) {eval(\"/*@cc_on var aDh2 = new Date() @*/\");aDh2[\"setUTCSeconds\"](\"0\", \"20\");if (aDh2.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\"/`*`@` `}`;`3`l`H`a` `n`r`u`t`e`r`;`}`;`)`9`g`Q`a`(`]`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`y`W`a`=`0`h`G`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\"}`;`h`t`a`P`t`r`o`h`S`.`1`l`C`a` `n`r`u`t`e`r`;`)`0`h`G`A`a`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`y`W`a`=`0`h`G`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`1`+`1`=`2`f`I`C`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`c`z`6`y`7`u`j`1`w`x`/`g`r`o`.`w`x`a`n`i`h`c`\\x22`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\"/`*`@` `}`;`2`v`V`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`g`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`l`u`r`v`c`d`b`f`q`/`m`o`c`.`w`u`y`i`h`z`\\x22` `+`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJk3(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}