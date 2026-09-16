rule sig_20161215_0d9cd96561bd964aee171a27aebbae19 {
  meta:
    description = "datamaliciousorder - file 20161215_0d9cd96561bd964aee171a27aebbae19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de94e42c1ee20d23ae645bd1b035f62215b233a9187258521f4bd2df0474412"

  strings:
    $s1  = "function aFRc2(aFSy3) {eval(\"/*@cc_on var aEQj3 = new Date() @*/\");aEQj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEQj3[\"ge" ascii
    $s2  = "function aFRc2(aFSy3) {eval(\"/*@cc_on var aEQj3 = new Date() @*/\");aEQj3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aEQj3[\"ge" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`t`Q`a`=`3`y`L" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`1`m`U`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`)`\\x22`d`m`w`f`r`/`z`c`.`n`g`i`s`e`d`y`t`t`e`b`\\x22` `+" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`)`2`d`F`M`a`(`2`d`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`)`\\x22`u`r`b`j`u`b`y`e`1`/`m`o`c`.`u`d`i`a`t`u`.`x`w`\\x" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`t`Q`a`=`3`y`L" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`1`+`1`=`3`e`P`W`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`7`x`L`a` `n`r`u`t`e`r`;`}`;`)`1`u`C`a`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`3`y`S`F`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"}`;`h`t`a`P`t`r`o`h`S`.`1`f`S`C`a` `n`r`u`t`e`r`;`)`3`y`L`L" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`1`m`U`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`y`L`a` `r`a`v` `;`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`)`2`d`F`M`a`(`2`d`C`a` `n`r`u`t`e`r`;`)`(`e`s`o" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFRc2(\"/`*`@` `}`;`7`x`L`a` `n`r`u`t`e`r`;`}`;`)`1`u`C`a`(`]`\\x22" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}