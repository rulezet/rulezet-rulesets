rule sig_20161214_127efc203155ce380b07c990aab750bf {
  meta:
    description = "datamaliciousorder - file 20161214_127efc203155ce380b07c990aab750bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fa1524a40ea6dcc09912dfdb081e254fc7306e9402a223180b0ced2cc2493cb"

  strings:
    $s1  = "function aFw4(aXNj1) {eval(\"/*@cc_on var aFYk8 = new Date() @*/\");aFYk8[\"setUTCSeconds\"](\"0\", \"20\");if (aFYk8.getUTCMill" ascii
    $s2  = "function aFw4(aXNj1) {eval(\"/*@cc_on var aFYk8 = new Date() @*/\");aFYk8[\"setUTCSeconds\"](\"0\", \"20\");if (aFYk8.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s4  = "().toString(10) == \"20\") {var aWNh1 = aXNj1[\"split\"](\"`\"); return aWNh1.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`1`h`N`W`a` `n`r`u`t`e`r`;`}`;`)`1`k`I`Q`a`(`]`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`0` `=` `0`a`Q`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`p`h`c`y`l`a`h`l`d`/`d`i`.`o`g`.`b`a`k`a`y`a`r`s`a`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`1`j`N`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`1`j`N`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`q`j`s`v`b`/`m`o`c`.`e`r`a`p`s`i`h`s`.`o`m`e`d`\\x2" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`)`5`i`W`F`a`(`2`z`T`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`1`h`N`W`a` `n`r`u`t`e`r`;`}`;`)`1`k`I`Q`a`(`]`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aFw4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`4`s`B`S`a`;`)`2` `,`5`s`F`a`(`]`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}