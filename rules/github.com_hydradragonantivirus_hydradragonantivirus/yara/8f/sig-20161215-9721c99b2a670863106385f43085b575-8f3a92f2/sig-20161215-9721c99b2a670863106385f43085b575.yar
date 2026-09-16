rule sig_20161215_9721c99b2a670863106385f43085b575 {
  meta:
    description = "datamaliciousorder - file 20161215_9721c99b2a670863106385f43085b575.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea5c97a1bd6958a9835a353f3a409c298fd9966d5e491c15ef4d76a094fc5a16"

  strings:
    $s1  = "function aGq0(aQh1) {eval(\"/*@cc_on var aVYi3 = new Date() @*/\");aVYi3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVYi3[\"getU" ascii
    $s2  = "function aGq0(aQh1) {eval(\"/*@cc_on var aVYi3 = new Date() @*/\");aVYi3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aVYi3[\"getU" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `4`l`A`V`a` `r`a`v` `;`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`6`p`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`z`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"\")), 1);" fullword ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`1`h`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`)`5`b`W`S`a`(`2`g`K`a` `n`r`u`t`e`r`;`)`(`e`s`o`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`1`h`Q`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s11 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`2`s`R`X`a` `+` `0`q`C`a`=`9`m`L`a` `r`a`v\")), 1);" fullword ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`6`p`I`a` `n`r`u`t`e`r`;`}`;`]`h`t`g`n`e`l`.`3`z`" ascii
    $s14 = "nds\"]()[\"toString\"](10) == \"20\") {var aLKo2 = aQh1[\"split\"](\"`\"); return aLKo2[\"reverse\"]().join(\"\");} else return " ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`2`o`K`L`a` `n`r`u`t`e`r`;`}`;`)`4`i`Y`a`(`]`\\x2" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"}`;`h`t`a`P`t`r`o`h`S`.`3`j`U`a` `n`r`u`t`e`r`;`)`1`a`P`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`2`o`K`L`a` `n`r`u`t`e`r`;`}`;`)`4`i`Y`a`(`]`\\x2" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `9`m`L`a`=`1`a`P`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\";`)`\\x22`m`k`5`z`k`7`n`/`s`e`.`l`e`d`a`p`s`u`r`o`c`\\x22` `" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aGq0(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`7`q`A`N`a`;`)`2` `,`0`j`U`Z`a`(`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}