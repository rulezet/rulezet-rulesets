rule sig_20161214_f0af1c6ee4863a75e1f7e32a033b669b {
  meta:
    description = "datamaliciousorder - file 20161214_f0af1c6ee4863a75e1f7e32a033b669b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be4d351a1ff8dc75b01fbc5140485187e74df1a107b2fa611fa2a2d3b33b79b7"

  strings:
    $s1  = "function aJNl5(aBz0) {eval(\"/*@cc_on var aQOx9 = new Date() @*/\");aQOx9[\"setUTCSeconds\"](\"0\", \"20\");if (aQOx9.getUTCMill" ascii
    $s2  = "function aJNl5(aBz0) {eval(\"/*@cc_on var aQOx9 = new Date() @*/\");aQOx9[\"setUTCSeconds\"](\"0\", \"20\");if (aQOx9.getUTCMill" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`\\x22`w`s`m`i`D`j`Z`K`q`8`y`2`l`w`m`3`5`J`v`f`i`i`M`f`s`m" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`d`M`a`=`5`i`U" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`3`n`Z`E`a` `n`r`u`t`e`r`;`}`;`)`1`v`G`J`a`(`]`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`)`\\x22`m`a`1`q`z`z`4`/`l`n`.`e`d`o`h`t`e`m`k`n`a`l`s`\\x" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`8`r`B`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4`s" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`)`'`/`%`P`M`E`T`%`'`(`]`'`s`g`n`i`r`t`S`t`n`e`m`n`o`r`i`v" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"}`;`h`t`a`P`t`r`o`h`S`.`0`f`N`I`a` `n`r`u`t`e`r`;`)`5`i`U`a" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`0`z`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`)`\\x22`q`z`2`b`z`i`g`/`g`r`o`.`t`u`m`a`l`a`m`\\x22` `+` " ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`0` `=` `8`n`K`a` `r`a`v\")), 1);" fullword ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`0`z`B`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`1`+`1`=`2`f`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `7`d`M`a`=`5`i`U" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`)`\\x22`g`i`d`d`1`/`u`r`.`o`n`i`j`y`m`.`8`8`c`i`l`o`r`c`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aJNl5(\";`1`+`1`=`2`f`H`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s20 = "().toString(10) == \"20\") {var aEZn3 = aBz0[\"split\"](\"`\"); return aEZn3.reverse().join(\"\");} else return \"\";};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}