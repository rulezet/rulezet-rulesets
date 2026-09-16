rule sig_20161214_d141cef0cfd4915df6b80f2dcf4b301e {
  meta:
    description = "datamaliciousorder - file 20161214_d141cef0cfd4915df6b80f2dcf4b301e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7ded67e2f56fad43fd2c147b9f3e7ec975033f1a3e161cbeb8e40dfb13731c5"

  strings:
    $s1  = "function aQIz4(aXYw0) {eval(\"/*@cc_on var aSRq4 = new Date() @*/\");aSRq4[\"setUTCSeconds\"](\"0\", \"20\");if (aSRq4.getUTCMil" ascii
    $s2  = "function aQIz4(aXYw0) {eval(\"/*@cc_on var aSRq4 = new Date() @*/\");aSRq4[\"setUTCSeconds\"](\"0\", \"20\");if (aSRq4.getUTCMil" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`\\x22`b`4`b`f`e`a`w`m`/`u`a`.`m`o`c`.`r`e`d`i`s`n`i`l`e" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`0`w`Y`X`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`v`K`a` `n`r`u`t`e`r`;`)`6`o`Q`H`a" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`k`T`Q`a`;`)`2` `,`5`y`Y`J`a`(" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`9`w`S`a` `n`r`u`t`e`r`;`}`;`)`8`s`E`M`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`(`y`a`r`r`A` `w`e`n` `=` `7`u`U`a` `r`a`v` ` ` ` \")), " ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`9`u`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`f" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`)`0`r`J`a`(`8`y`D`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aQIz4(\"/`*`@` `}`;`9`u`X`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`7`f" ascii
    $s20 = "s().toString(10) == \"20\") {var aSw9 = aXYw0[\"split\"](\"`\"); return aSw9.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}