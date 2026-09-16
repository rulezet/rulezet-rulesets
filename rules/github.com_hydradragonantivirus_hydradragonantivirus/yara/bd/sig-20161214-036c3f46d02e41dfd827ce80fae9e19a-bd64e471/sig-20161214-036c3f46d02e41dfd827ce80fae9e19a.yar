rule sig_20161214_036c3f46d02e41dfd827ce80fae9e19a {
  meta:
    description = "datamaliciousorder - file 20161214_036c3f46d02e41dfd827ce80fae9e19a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f4ccdb72ef195a7d72e5bdc01290a9e2bdc68aef00ce9316fd676bdc7bc35dc"

  strings:
    $s1  = "function aKIv5(aTOt1) {eval(\"/*@cc_on var aXr1 = new Date() @*/\");aXr1[\"setUTCSeconds\"](\"0\", \"20\");if (aXr1.getUTCMillis" ascii
    $s2  = "function aKIv5(aTOt1) {eval(\"/*@cc_on var aXr1 = new Date() @*/\");aXr1[\"setUTCSeconds\"](\"0\", \"20\");if (aXr1.getUTCMillis" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`a`g`9`d`2`h`6`b`i`k`/`n`c`.`3`2`1`d`y`f`\\x22` `+" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`0` `=` `2`t`D`K`a` `r`a`v\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"/`*`@` `}`;`2`c`P`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`8`v" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`1`+`1`=`2`j`U`Z`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"/`*`@` `}`;`7`a`U`X`a` `n`r`u`t`e`r`;`}`;`)`4`i`X`a`(`]`\\x" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`(`y`a`r`r`A` `w`e`n` `=` `5`e`D`E`a` `r`a`v` ` ` ` \"))" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`h`J`a` `n`r`u`t`e`r`;`)`0`q`D`V`a" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"/`*`@` `}`;`)`0`t`H`B`a`(`5`z`J`O`a` `n`r`u`t`e`r`;`)`(`e`s" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`n`g`h`b`5`k`/`m`o`c`.`8`6`6`0`\\x22` `+` `2`j`O`K" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`)`\\x22`e`e`u`n`p`t`e`a`e`f`/`m`o`c`.`o`y`u`o`s`u`o`s`.`t" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"}`;`h`t`a`P`t`r`o`h`S`.`5`h`J`a` `n`r`u`t`e`r`;`)`0`q`D`V`a" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aKIv5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}