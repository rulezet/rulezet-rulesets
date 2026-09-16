rule sig_20161215_d62195895f9283c9d834a0f69dbe1a81 {
  meta:
    description = "datamaliciousorder - file 20161215_d62195895f9283c9d834a0f69dbe1a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79ad91717809c863ce1c8c9012e88bfbd6090f0323d3778ffd05a43c11e78fe5"

  strings:
    $s1  = "function aGk0(aHw9) {eval(\"/*@cc_on var aWDc4 = new Date() @*/\");aWDc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWDc4[\"getU" ascii
    $s2  = "function aGk0(aHw9) {eval(\"/*@cc_on var aWDc4 = new Date() @*/\");aWDc4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWDc4[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`u`u`1`d`m`q`/`u`a`.`t`e`n`.`s`l`e`e`h`w`n`o`k`l`a`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`0`e`I`T`a` `+` `2`s`L`Z`a`=`2`u`V`a` `r`a`v\")), 1);" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`u`V`a`=`0`l`H`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`v`u`3`e`t`t`f`f`g`/`m`o`c`.`1`-`s`d`b`.`w`w`w`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `7`b`F`M`a` `r`a`v` `;`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`0` `=` `5`h`T`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`9`w`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`9`w`H`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `2`u`V`a`=`0`l`H`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\";`)`\\x22`l`y`k`0`o`n`r`t`c`i`/`m`o`c`.`s`r`e`i`r`r`e`t`x`o`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`)`0`e`G`U`a`(`6`i`I`K`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGk0(\"/`*`@` `}`;`9`r`P`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}