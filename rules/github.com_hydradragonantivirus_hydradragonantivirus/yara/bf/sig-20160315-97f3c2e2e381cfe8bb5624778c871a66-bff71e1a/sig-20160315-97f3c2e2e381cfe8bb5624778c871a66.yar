rule sig_20160315_97f3c2e2e381cfe8bb5624778c871a66 {
  meta:
    description = "datamaliciousorder - file 20160315_97f3c2e2e381cfe8bb5624778c871a66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d509d2c372651bf3466a8fb7520d5084bcc44e268f77b49e03dabdb0a7f0abf"

  strings:
    $s1  = "    TSSOlzik = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "rating = kJEWGUDIL[3 * 5 - 3 * 3].split(\"aflame\").join(\"\");" fullword ascii
    $s3  = "luDfmi.onreadystatechange = function () {" fullword ascii
    $s4  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "String.prototype.digest = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "        ivDpTcD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s7  = "ogOrGDdr = \" filter: {\";" fullword ascii
    $s8  = "    luDfmi[protects + (\"acrobat\",\"pointers\",\"jamaica\",\"allpowerful\",\"e\") + ((\"recipients\", \"veteran\", \"NLBhcWPCCQ" ascii
    $s9  = "var xqoCpK = this[rating];" fullword ascii
    $s10 = "volga\",\"pithy\",\".e\")+(\"coasting\",\"innermost\",\"always\",\"xe\"), false);" fullword ascii
    $s11 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s12 = "jDWyOt = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s13 = "        ivDpTcD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s14 = "    TSSOlzik = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s15 = "        HoUGQjxUu = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s16 = "        yPuDLFWrkY = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    jMdcX[kJEWGUDIL[vindictiveI+1]](UJePJezQ, 1, \"HMoKLrM\" === \"nPKbKuMvn\"); eTXjx = \"  \\\"TAG\\\": function( nodeNameSele" ascii
    $s18 = "} catch (JzKAnwz) { };" fullword ascii

  condition:
    uint16(0) == 0x5957 and
    8 of them
}