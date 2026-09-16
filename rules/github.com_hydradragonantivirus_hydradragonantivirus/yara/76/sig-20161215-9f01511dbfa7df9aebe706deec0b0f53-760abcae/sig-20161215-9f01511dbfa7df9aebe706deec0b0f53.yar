rule sig_20161215_9f01511dbfa7df9aebe706deec0b0f53 {
  meta:
    description = "datamaliciousorder - file 20161215_9f01511dbfa7df9aebe706deec0b0f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d3774a63e34da121484df45f63f51a54eabd7faa591335c9bc00e711e7ae22"

  strings:
    $s1  = "function aVe1(aNp6) {eval(\"/*@cc_on var aZu3 = new Date() @*/\");aZu3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZu3[\"getUTCM" ascii
    $s2  = "function aVe1(aNp6) {eval(\"/*@cc_on var aZu3 = new Date() @*/\");aZu3[\"setUTC\"+\"Seconds\"](\"0\", \"20\");if (aZu3[\"getUTCM" ascii
    $s3  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`\\x22`k`\\x22` `+` `\\x22`z`.`\\x22` `+` `4`d`F`a`=`7`i`P`" ascii
    $s4  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"/`*`@` `}`;`}`;`e`u`n`i`t`n`o`c`{` `)`e`(` `h`c`t`a`c`}`;`k`" ascii
    $s5  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s6  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`\\x22`/`\\x22`+`\\x22`/`\\x22`+`\\x22`:`\\x22`+`\\x22`p`" ascii
    $s7  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `1`r`" ascii
    $s8  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"/`*`@` `}`;`)`3`b`U`I`a`(`7`j`X`P`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s9  = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`u`u`t`h`l`k`w`t`6`/`m`o`c`.`z`a`p`o`l`b`a`p`\\x22`" ascii
    $s10 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`z`c`x`t`e`w`v`e`6`/`z`i`b`.`e`r`o`c`i`n`u`m`m`o`c`" ascii
    $s11 = "\"]()[\"toString\"](10) == \"20\") {var aARg3 = aNp6[\"split\"](\"`\"); return aARg3[\"reverse\"]().join(\"\");} else return \"" ascii
    $s12 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"/`*`@` `}`;`)`(`e`s`o`l`c`.`6`q`W`X`a`;`)`2` `,`7`j`B`a`(`]`" ascii
    $s13 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`k`i`j`x`e`/`i`l`.`o`i`t`a`\\x22` `+` `1`r`A`a`(`h`" ascii
    $s14 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"/`*`@` `}`;`6`p`N`a` `n`r`u`t`e`r`;`)`\\x22`\\x22`(`]`\\x22`" ascii
    $s15 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`c`1`s`b`b`g`/`l`p`.`m`a`e`r`d`s`a`\\x22` `+` `1`r`" ascii
    $s16 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"}`;`h`t`a`P`t`r`o`h`S`.`2`z`J`a` `n`r`u`t`e`r`;`)`7`i`P`a`(`" ascii
    $s17 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`\\x22`i`J`o`b`R`G`U`A`N`\\x22` `=` `6`f`O`a` `r`a`v` `;`" ascii
    $s18 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\"/`*`@` `}`;`)`3`b`U`I`a`(`7`j`X`P`a` `n`r`u`t`e`r`;`)`(`e`s`" ascii
    $s19 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`l`l`e`h`S`.`t`p`i`r`c`S`W`\\x22`(`t`c`e`j`b`O`X`e`" ascii
    $s20 = "var v_ccdd = (new Function(\"dfff\", \"return dfff;\"), eval(aVe1(\";`)`\\x22`P`T`T`H`L`M`X`.`2`L`M`X`S`M`\\x22`(`t`c`e`j`b`O`X`" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}