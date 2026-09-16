rule sig_20161214_ab257ff325a1bedd99e71bc52b179922 {
  meta:
    description = "datamaliciousorder - file 20161214_ab257ff325a1bedd99e71bc52b179922.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d96fe12555608da3f83664c58159699c9aaed8476650a78cdbfdde85bde2aaa5"

  strings:
    $s1  = "function aBt2(aXd9) {eval(\"/*@cc_on var aEg0 = new Date() @*/\");aEg0[\"setUTCSeconds\"](\"0\", \"20\");if (aEg0.getUTCMillisec" ascii
    $s2  = "function aBt2(aXd9) {eval(\"/*@cc_on var aEg0 = new Date() @*/\");aEg0[\"setUTCSeconds\"](\"0\", \"20\");if (aEg0.getUTCMillisec" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`n`q`y`n`s`2`z`5`m`l`/`m`o`c`.`9`9`9`d`c`d`w`\\x22`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`v`z`g`l`n`r`8`a`/`y`u`.`o`d`n`u`m`o`n`c`e`t`\\x22`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\"/`*`@` `}`;`9`m`K`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`a`c`4`e`q`k`/`m`o`c`.`8`1`3`x`t`\\x22` `+` `1`x`H`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`f`E`a` `r`a`v` ` ` ` \")), 1" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\"\")), 1);" fullword ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\"/`*`@` `}`;`9`m`K`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\"}`;`h`t`a`P`t`r`o`h`S`.`4`n`O`K`a` `n`r`u`t`e`r`;`)`5`c`U`Q`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`7`m`L`a` `+` `1`n`P`G`a`=`9`o`H`a` `r`a`v\")), 1);" fullword ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`o`H`a`=`5`c`U`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s19 = "oString(10) == \"20\") {var aNJe2 = aXd9[\"split\"](\"`\"); return aNJe2.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aBt2(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}