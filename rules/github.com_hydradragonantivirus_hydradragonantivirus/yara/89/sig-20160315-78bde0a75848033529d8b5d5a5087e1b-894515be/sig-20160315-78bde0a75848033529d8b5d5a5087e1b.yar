rule sig_20160315_78bde0a75848033529d8b5d5a5087e1b {
  meta:
    description = "datamaliciousorder - file 20160315_78bde0a75848033529d8b5d5a5087e1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7339077e245f10d5c06c3b1f42d34cf0ecc181b6b3d672a1c79a2124ddb54c8d"

  strings:
    $s1  = "    CqoatXn = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "organizer = jraTJ[3 * 5 - 3 * 3].split(\"biology\").join(\"\");" fullword ascii
    $s3  = ")+\"io\"+\"lo\"+\"gy.\" + (\"chime\",\"electron\",\"herbs\",\"S\"), \"byxttX\", \"h\"+\"biol\"+(\"techrepublic\",\"harboured\"," ascii
    $s4  = "ixFyhET.onreadystatechange = function () {" fullword ascii
    $s5  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.galaxy = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "        bknJYbvrV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s9  = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s10 = "zle.error( match[0] );     \";" fullword ascii
    $s11 = "    ixFyhET.open(\"G\"+(\"saucepan\",\"walking\",\"ET\"), \"h\"+\"tt\"+\"p:\"+\"//\"+(\"connecting\",\"presentations\",\"begone" ascii
    $s12 = "var qdVbSAiw = this[organizer];" fullword ascii
    $s13 = "\",\"coerce\",\"contrast\",\"is\")+\"s.\"+\"cz\"+\"/87yg756\"+\"f5\"+\".e\"+\"xe\", false);" fullword ascii
    $s14 = "QaMufGcVCQt = \" filter: {\";" fullword ascii
    $s15 = "\"YT\"+\"GkFo\", \"E\"+(\"instrumentality\",\"unwisely\",\"transformation\",\"xp\")+\"an\"+(\"richmond\",\"undefiled\",\"dEnvir" ascii
    $s16 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s17 = "        bknJYbvrV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s18 = "LuIernJVO = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s19 = "        LBDFTXNnB = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "        oVqPzlJy = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii

  condition:
    uint16(0) == 0x6d6d and
    8 of them
}