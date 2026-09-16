rule sig_20160315_45d7527f23d21bac84e84b3dcd21fca8 {
  meta:
    description = "datamaliciousorder - file 20160315_45d7527f23d21bac84e84b3dcd21fca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "915077d1a89948b507e14c9042d26700d3caf4cb6b6492ca84fdaa1d8476af5f"

  strings:
    $s1  = "    SDhUKQLj = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "    wKcnFTAmA.open((\"succinct\",\"dramatic\",\"behest\",\"hilarity\",\"G\")+\"ET\", \"htt\"+\"p:\"+(\"paper\",\"reload\",\"econ" ascii
    $s3  = "ed\",\"exactitude\",\"measure\",\"un\"), \"A\"+\"ctco\"+\"lo\"+\"ss\"+\"us\"+\"ivcolo\"+(\"blockade\",\"london\",\"attempts\",\"" ascii
    $s4  = "wKcnFTAmA.onreadystatechange = function () {" fullword ascii
    $s5  = "= +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "String.prototype.inverness = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "        TKoVFrfmg = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s8  = "zle.error( match[0] );     \";" fullword ascii
    $s9  = "m/87y\"+(\"cockney\",\"worcestershire\",\"refined\",\"g7\")+\"56f5\"+\".e\"+\"xe\", false);" fullword ascii
    $s10 = "var bwVqYKRT = this[uganda];" fullword ascii
    $s11 = "XjQuVyAWPeY = \" filter: {\";" fullword ascii
    $s12 = "    match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );     m" ascii
    $s13 = "YMJHGzA = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        TKoVFrfmg = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s15 = "    SDhUKQLj = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s16 = "        KDzYWoIzn = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "        nimRzkQIyzl = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    ddjoOpS[wmadQBbdr[evokeI+1]](FDgkB, 1, \"iksbfMC\" === \"TDkoPQY\"); zyzyF = \"  \\\"TAG\\\": function( nodeNameSelector ) {" ascii
    $s19 = "} catch (XcnrenpM) { };" fullword ascii

  condition:
    uint16(0) == 0x7747 and
    8 of them
}