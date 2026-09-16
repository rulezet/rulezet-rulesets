rule sig_20161214_5e8d113b57c134452c533ad11365116f {
  meta:
    description = "datamaliciousorder - file 20161214_5e8d113b57c134452c533ad11365116f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae0faadd5cc43fa43bf513c5188f22e20037f39b6954143d62450e3871b91f54"

  strings:
    $s1  = "function aUQn9(aXw0) {eval(\"/*@cc_on var aWg1 = new Date() @*/\");aWg1[\"setUTCSeconds\"](\"0\", \"20\");if (aWg1.getUTCMillise" ascii
    $s2  = "function aUQn9(aXw0) {eval(\"/*@cc_on var aWg1 = new Date() @*/\");aWg1[\"setUTCSeconds\"](\"0\", \"20\");if (aWg1.getUTCMillise" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"/`*`@` `}`;`3`z`P`a` `n`r`u`t`e`r`;`}`;`)`1`l`S`a`(`]`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"/`*`@` `}`;`)`1`z`O`a`(`5`l`J`a` `n`r`u`t`e`r`;`)`(`e`s`o`l" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`u`e`2`j`d`q`u`p`9`z`/`m`o`c`.`5`6`3`u`h`n`a`i`j`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"}`;`h`t`a`P`t`r`o`h`S`.`6`w`J`a` `n`r`u`t`e`r`;`)`1`b`L`a`(" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `8`q`L`a`=`1`b`L" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"/`*`@` `}`;`3`z`P`a` `n`r`u`t`e`r`;`}`;`)`1`l`S`a`(`]`\\x22" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`n`h`5`d`o`0`/`e`a`.`t`n`e`m`n`o`r`i`v`n`e`\\x22` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"/`*`@` `}`;`4`s`O`D`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`z`9`f`w`y`e`p`f`e`e`/`m`o`c`.`e`c`i`v`r`e`s`e`n`e" ascii
    $s17 = "toString(10) == \"20\") {var aPz3 = aXw0[\"split\"](\"`\"); return aPz3.reverse().join(\"\");} else return \"\";};" fullword ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\";`)`\\x22`1`s`j`d`t`y`0`/`g`r`o`.`e`n`i`l`n`o`p`a`h`p`i`a`i" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aUQn9(\"}`;`h`t`a`P`t`r`o`h`S`.`6`w`J`a` `n`r`u`t`e`r`;`)`1`b`L`a`(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}