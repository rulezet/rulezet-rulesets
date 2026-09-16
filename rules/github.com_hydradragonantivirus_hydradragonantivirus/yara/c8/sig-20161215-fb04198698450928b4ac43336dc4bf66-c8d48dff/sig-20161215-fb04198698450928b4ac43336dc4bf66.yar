rule sig_20161215_fb04198698450928b4ac43336dc4bf66 {
  meta:
    description = "datamaliciousorder - file 20161215_fb04198698450928b4ac43336dc4bf66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b473a093b43e0ec00bc4258dff013266023e174a9dedf134552ea68315683f"

  strings:
    $s1  = "function aVUk5(aYw8) {eval(\"/*@cc_on var aRXa8 = new Date() @*/\");aRXa8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRXa8[\"get" ascii
    $s2  = "function aVUk5(aYw8) {eval(\"/*@cc_on var aRXa8 = new Date() @*/\");aRXa8[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aRXa8[\"get" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `6`j`P`a`=`5`t`Z" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"}`;`h`t`a`P`t`r`o`h`S`.`4`k`N`P`a` `n`r`u`t`e`r`;`)`5`t`Z`B" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"/`*`@` `}`;`5`w`H`a` `n`r`u`t`e`r`;`}`;`)`7`x`H`a`(`]`\\x22" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`1`+`1`=`6`a`A`a` `r`a`v`;`)`\\x22`t`c`e`j`b`O`m`e`t`s`y`S" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"/`*`@` `}`;`8`w`Y`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`7`o`k`y`5`l`s`/`l`p`.`i`n`h`c`u`k`o`d`o`k`t`s`y`z" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"/`*`@` `}`;`5`w`H`a` `n`r`u`t`e`r`;`}`;`)`7`x`H`a`(`]`\\x22" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`y`b`c`h`j`/`m`o`c`.`c`n`i`l`o`s`h`c`e`t`i`h`\\x22" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\"/`*`@` `}`;`9`c`T`A`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`4" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`6`g`g`s`1`q`z`f`g`i`/`m`o`c`.`r`o`o`d`t`u`o`d`b`b" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVUk5(\";`)`\\x22`v`v`6`c`z`a`d`f`u`/`u`r`.`s`t`r`e`s`t`u`o`h`u`b`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}