rule sig_20161215_0d14bfbc20a4684ef93ebb864094974c {
  meta:
    description = "datamaliciousorder - file 20161215_0d14bfbc20a4684ef93ebb864094974c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7fc4480564c247117cb91816a31babd502dead2022716853c5798d6784e061c"

  strings:
    $s1  = "function aAd4(aTj3) {eval(\"/*@cc_on var aKJk7 = new Date() @*/\");aKJk7[\"setUTCSeconds\"](\"0\", \"20\");if (aKJk7.getUTCMilli" ascii
    $s2  = "function aAd4(aTj3) {eval(\"/*@cc_on var aKJk7 = new Date() @*/\");aKJk7[\"setUTCSeconds\"](\"0\", \"20\");if (aKJk7.getUTCMilli" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`z`V`Q`a`;`)`2` `,`0`k`A`L`a`(`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `0`r`V`U`a`=`5`h`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"}`;`h`t`a`P`t`r`o`h`S`.`9`s`P`a` `n`r`u`t`e`r`;`)`5`h`V`a`(`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`0`v`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`u`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`2`a`O`K`a` `+` `5`d`M`a`=`0`r`V`U`a` `r`a`v\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`1`+`1`=`7`v`E`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`)`\\x22`u`6`b`s`z`y`p`d`/`m`o`c`.`b`g`s`o`f`e`d`e`h`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`3`z`V`Q`a`;`)`2` `,`0`k`A`L`a`(`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`0`v`S`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`u`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\"/`*`@` `}`;`6`t`M`U`a` `n`r`u`t`e`r`;`}`;`)`8`f`J`a`(`]`\\x2" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aAd4(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}