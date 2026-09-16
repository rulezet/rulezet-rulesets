rule sig_20161215_ee8d8fa8a8f1c83bcf925e3e26f22222 {
  meta:
    description = "datamaliciousorder - file 20161215_ee8d8fa8a8f1c83bcf925e3e26f22222.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3ab1fa8f2ca07cb22dc06c84ddc99fee95ccb872852ee7457a36ec2c3a025fd"

  strings:
    $s1  = "function aAl2(aTVz2) {eval(\"/*@cc_on var aWt4 = new Date() @*/\");aWt4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWt4[\"getUTC" ascii
    $s2  = "function aAl2(aTVz2) {eval(\"/*@cc_on var aWt4 = new Date() @*/\");aWt4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aWt4[\"getUTC" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`x`D`a`;`)`2` `,`0`e`U`Z`a`(`]`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` `" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"/`*`@` `}`;`2`z`V`T`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`\\x22`2`b`m`u`k`r`5`/`m`o`c`.`u`4`h`2`\\x22` `+` `3`x`W`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"/`*`@` `}`;`)`6`g`I`X`a`(`9`l`G`U`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"}`;`h`t`a`P`t`r`o`h`S`.`9`b`P`a` `n`r`u`t`e`r`;`)`3`r`Q`a`(`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`s`R`B`a` `r`a`v` `;`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"/`*`@` `}`;`2`j`Q`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`b`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`x`D`a`;`)`2` `,`0`e`U`Z`a`(`]`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\"}`;`h`t`a`P`t`r`o`h`S`.`9`b`P`a` `n`r`u`t`e`r`;`)`3`r`Q`a`(`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `3`s`R`B`a` `r`a`v` `;`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAl2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`r`O`a`=`3`r`Q`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}