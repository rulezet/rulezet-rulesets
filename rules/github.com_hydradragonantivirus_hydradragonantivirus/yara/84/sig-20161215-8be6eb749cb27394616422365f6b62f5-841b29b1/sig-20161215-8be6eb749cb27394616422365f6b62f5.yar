rule sig_20161215_8be6eb749cb27394616422365f6b62f5 {
  meta:
    description = "datamaliciousorder - file 20161215_8be6eb749cb27394616422365f6b62f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19ae7698933280acdd28a129ec623339f0d5f344680047491cc71a3e0d42e356"

  strings:
    $s1  = "function aWv4(aEf2) {eval(\"/*@cc_on var aQOd4 = new Date() @*/\");aQOd4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQOd4[\"getU" ascii
    $s2  = "function aWv4(aEf2) {eval(\"/*@cc_on var aQOd4 = new Date() @*/\");aQOd4[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aQOd4[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\"/`*`@` `}`;`1`e`R`J`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`0`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`8`z`O`a`;`)`2` `,`4`g`R`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`0` `=` `4`h`O`Q`a` `r`a`v\")), 1);" fullword ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\"/`*`@` `}`;`7`q`U`S`a` `n`r`u`t`e`r`;`}`;`)`7`i`K`a`(`]`\\x2" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\"/`*`@` `}`;`)`1`l`F`a`(`1`x`I`G`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `2`e`E`a` `r`a`v` `;`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`j`D`a`=`7`w`G`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`k`S`W`a` `n`r`u`t`e`r`;`)`7`w`G`a`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`1`+`1`=`9`w`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`2`z`m`u`4`/`k`u`.`o`c`.`p`o`h`s`e`m`i`l`b`u`s`\\x2" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`)`\\x22`d`t`r`2`l`s`4`/`r`f`.`1`1`1`1`m`f`\\x22` `+` `9`l`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`1`+`1`=`9`w`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aWv4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `5`j`D`a`=`7`w`G`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}