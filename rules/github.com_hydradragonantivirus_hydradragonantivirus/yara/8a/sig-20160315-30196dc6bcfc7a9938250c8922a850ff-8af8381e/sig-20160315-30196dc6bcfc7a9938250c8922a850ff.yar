rule sig_20160315_30196dc6bcfc7a9938250c8922a850ff {
  meta:
    description = "datamaliciousorder - file 20160315_30196dc6bcfc7a9938250c8922a850ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "600c39cf2bb86a6da9ab18a8e1902883479af7e9c8ed5375c42d49fa29426645"

  strings:
    $s1  = "    fnKtQd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s2  = "y\",\"disarm\",\"tech.net/8\")+\"7y\"+\"g756f5\"+(\"early\",\"ecological\",\"leaks\",\"honeysuckle\",\".exe\"), false);" fullword ascii
    $s3  = "dialectic = WJbQobB[3 * 5 - 3 * 3].split(\"diverse\").join(\"\");" fullword ascii
    $s4  = "String.prototype.passing = function () { return this.substr(0, 1); };" fullword ascii
    $s5  = "DYJczhu.onreadystatechange = function () {" fullword ascii
    $s6  = "eece\",\"W\")+(\"quotes\",\"autograph\",\"Scdi\")+(\"meekness\",\"lamps\",\"insured\",\"vers\")+\"eriptdiverse.\" + (\"illegitim" ascii
    $s7  = "    DYJczhu.open((\"signs\",\"pockets\",\"bouncing\",\"benin\",\"G\")+\"ET\", (\"embedded\",\"formation\",\"h\")+\"ttp://demo.es" ascii
    $s8  = "   (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "    WccJJx[WJbQobB[apologizeI+1]](XAeGEq, 1, \"GqMWLCGnn\" === \"zrBdioIhKf\"); Efudf = \"  \\\"TAG\\\": function( nodeNameSelec" ascii
    $s10 = "        dqNWhzuDydo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s11 = "izzle.error( match[0] );     \";" fullword ascii
    $s12 = "t excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis  " ascii
    $s13 = "var YHenajj = this[dialectic];" fullword ascii
    $s14 = "    WccJJx[WJbQobB[apologizeI+1]](XAeGEq, 1, \"GqMWLCGnn\" === \"zrBdioIhKf\"); Efudf = \"  \\\"TAG\\\": function( nodeNameSelec" ascii
    $s15 = "cgCBdH = \" filter: {\";" fullword ascii
    $s16 = "YqJLeum = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "        dqNWhzuDydo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s18 = "    fnKtQd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s19 = "        CnXApLtheMs = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "        EBsTYmdEXF = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii

  condition:
    uint16(0) == 0x547a and
    8 of them
}