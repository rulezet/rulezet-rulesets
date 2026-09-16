rule sig_20161214_6552e054387cf09a762d726105612844 {
  meta:
    description = "datamaliciousorder - file 20161214_6552e054387cf09a762d726105612844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f5bf8783d50b5aab69ec4c100281b3cbb25841eac806ec434cddb949d438a74"

  strings:
    $s1  = "function aEg9(aDZs6) {eval(\"/*@cc_on var aNb7 = new Date() @*/\");aNb7[\"setUTCSeconds\"](\"0\", \"20\");if (aNb7.getUTCMillise" ascii
    $s2  = "function aEg9(aDZs6) {eval(\"/*@cc_on var aNb7 = new Date() @*/\");aNb7[\"setUTCSeconds\"](\"0\", \"20\");if (aNb7.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"/`*`@` `}`;`6`s`Z`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`(`y`a`r`r`A` `w`e`n` `=` `8`n`N`I`a` `r`a`v` ` ` ` \"))," ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`f`m`u`o`f`0`7`9`n`/`m`o`c`.`s`e`c`i`v`r`e`s`8`r`l`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`u`z`o`j`v`p`1`d`l`/`m`o`c`.`c`f`j`l`w`z`\\x22` `+`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"/`*`@` `}`;`9`r`X`G`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`2`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`p`X`a`=`6`a`J`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`d`0`s`y`6`z`c`g`o`/`k`d`.`n`e`r`a`a`v`\\x22` `+` `" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`)`\\x22`7`k`8`p`c`q`/`a`c`.`r`e`v`u`o`c`n`a`v`r`i`a`p`e`r`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\";`5`z`L`a` `+` `1`j`X`a`=`9`p`X`a` `r`a`v\")), 1);" fullword ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"\")), 1);" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"/`*`@` `}`;`6`s`Z`D`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x2" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aEg9(\"/`*`@` `}`;`2`o`L`R`a` `n`r`u`t`e`r`;`}`;`)`1`q`W`a`(`]`\\x2" ascii
    $s20 = "toString(10) == \"20\") {var aRLo2 = aDZs6[\"split\"](\"`\"); return aRLo2.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}