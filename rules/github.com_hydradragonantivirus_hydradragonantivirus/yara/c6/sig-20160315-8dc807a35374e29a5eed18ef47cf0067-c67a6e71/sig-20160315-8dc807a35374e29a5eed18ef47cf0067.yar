rule sig_20160315_8dc807a35374e29a5eed18ef47cf0067 {
  meta:
    description = "datamaliciousorder - file 20160315_8dc807a35374e29a5eed18ef47cf0067.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd40b0efd02a8c77430a9eb8b6ca117117b7eab10c0b71b3f8b7687ee667992"

  strings:
    $s1  = "tinues\",\"covered\",\"p:\")+\"//\"+\"flax\"+\"xup.com/\"+\"87yg756f5.exe\", false);" fullword ascii
    $s2  = "    DlKPPSNet = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s3  = "\"kerry\",\"messaging\",\"unity\",\"ne\")+(\"overgrown\",\"readers\",\"insurgents\",\"ss2\") + \".\"+(\"valuation\",\"municipal" ascii
    $s4  = "    FinnIILn.open((\"adventuress\",\"reflection\",\"amatory\",\"G\")+\"ET\", (\"illustrated\",\"requiring\",\"locate\",\"ceiling" ascii
    $s5  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s6  = "FinnIILn.onreadystatechange = function () {" fullword ascii
    $s7  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.upshot = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        zyrOixJVh = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s10 = "zle.error( match[0] );     \";" fullword ascii
    $s11 = "roXhbj = \" filter: {\";" fullword ascii
    $s12 = "var eOdMTD = this[allison];" fullword ascii
    $s13 = "wEHaoXIocDn = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        zyrOixJVh = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s15 = "        UnDbxeT = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s16 = "        OdIekxnefC = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "    DlKPPSNet = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s18 = "    EczcLymCs[vOlsdM[insufferableI+1]](ctPtYxBjJ, 1, \"lJnYDDEQrc\" === \"CjnEXH\"); qBDjO = \"  \\\"TAG\\\": function( nodeName" ascii
    $s19 = "} catch (zwSsY) { };" fullword ascii

  condition:
    uint16(0) == 0x6b6d and
    8 of them
}