rule sig_20161214_ea3ecbddeb85fda71ababcd3197d72bf {
  meta:
    description = "datamaliciousorder - file 20161214_ea3ecbddeb85fda71ababcd3197d72bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "182d8cd5ba2b6714aefcb90bc5bf852e7e42e395050c24ba71043064e4ceecf2"

  strings:
    $s1  = "function aSo0(aLJd6) {eval(\"/*@cc_on var aCj0 = new Date() @*/\");aCj0[\"setUTCSeconds\"](\"0\", \"20\");if (aCj0.getUTCMillise" ascii
    $s2  = "function aSo0(aLJd6) {eval(\"/*@cc_on var aCj0 = new Date() @*/\");aCj0[\"setUTCSeconds\"](\"0\", \"20\");if (aCj0.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`l`W`a`=`5`c`N`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z`" ascii
    $s7  = "toString(10) == \"20\") {var aOd4 = aLJd6[\"split\"](\"`\"); return aOd4.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`0` `=` `3`j`U`a` `r`a`v\")), 1);" fullword ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\"/`*`@` `}`;`6`d`J`L`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`j`L`H`a`;`)`2` `,`0`c`I`a`(`]`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\"/`*`@` `}`;`)`1`h`A`a`(`2`s`G`P`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`9`v`W`U`a` `+` `9`s`I`a`=`6`l`W`a` `r`a`v\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`9`j`L`H`a`;`)`2` `,`0`c`I`a`(`]`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`1`+`1`=`2`g`G`B`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aSo0(\";`)`\\x22`7`w`1`o`y`d`/`m`o`c`.`n`g`i`s`e`d`m`e`r`a`u`q`s`.`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}