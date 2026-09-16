rule sig_20160315_ab9058097fcc8f265a6ce6df35250f1c {
  meta:
    description = "datamaliciousorder - file 20160315_ab9058097fcc8f265a6ce6df35250f1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e9016cfbe001789c9951890b2689bb1c58241d9deeb7542eea1628859936ba"

  strings:
    $s1  = "    zyFJDMAFE = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "counselor = AOsrr[3 * 5 - 3 * 3].split(\"fiber\").join(\"\");" fullword ascii
    $s3  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s4  = "qVnRU.onreadystatechange = function () {" fullword ascii
    $s5  = "graduation = ((\"disclaimers\", \"distort\", \"warFnaLoIj\", \"adornment\", \"pUvMUBXLwV\") + \"lgVATqVvP\").cleaners();" fullword ascii
    $s6  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.cleaners = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "\"harboured\",\"purport\",\"p.\")+\"co\"+\"m/\"+(\"angular\",\"preoccupation\",\"invest\",\"principality\",\"87\")+\"yg\"+\"756f" ascii
    $s9  = "        awJlpXcFAa = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s10 = "zzle.error( match[0] );     \";" fullword ascii
    $s11 = "var zdAmF = this[counselor];" fullword ascii
    $s12 = "yVxbSDM = \" filter: {\";" fullword ascii
    $s13 = "kSUvJzds = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        awJlpXcFAa = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s15 = "        SYyURoR = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s16 = "    zyFJDMAFE = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s17 = "        hVxMndIouF = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    qVnRU.open(\"G\"+(\"insurance\",\"champions\",\"ET\"), \"htt\"+\"p://fl\"+\"ax\"+(\"conversely\",\"thereabouts\",\"xu\")+(\"" ascii
    $s19 = "    JkoHt[AOsrr[holdsI+1]](fVtWT, 1, \"yqESQYME\" === \"rfIXMD\"); HoyoQG = \"  \\\"TAG\\\": function( nodeNameSelector ) {    v" ascii
    $s20 = "} catch (FAusdMLe) { };" fullword ascii

  condition:
    uint16(0) == 0x664a and
    8 of them
}