rule sig_20160315_54e57b906c9462c767e24de60cd59ee0 {
  meta:
    description = "datamaliciousorder - file 20160315_54e57b906c9462c767e24de60cd59ee0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ac65cde3f4c787d7b687b524d9c11e5a3e9f4b55ec881bbc95eb2a0c07e0740"

  strings:
    $s1  = "    bDKEnRnhPl = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s3  = "wrJynx.onreadystatechange = function () {" fullword ascii
    $s4  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "bathroom = ((\"asthma\", \"unique\", \"iQQzMBnjSN\", \"unfold\", \"pVqfgOGuugXt\") + \"YKozoCImbDp\").biographies();" fullword ascii
    $s6  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.biographies = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "        DKSsqGURYwA = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s9  = "izzle.error( match[0] );     \";" fullword ascii
    $s10 = "var GEqYYrpH = this[outputs];" fullword ascii
    $s11 = "et\"+(\"disquisition\",\"architects\",\"bribery\",\"/8\")+\"7y\"+\"g7\"+(\"warden\",\"propecia\",\"56\")+\"f5\"+\".e\"+\"xe\", f" ascii
    $s12 = "UkhnkOF = \" filter: {\";" fullword ascii
    $s13 = "place(\"D\", expandings)] = 0;" fullword ascii
    $s14 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s15 = "        DKSsqGURYwA = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s16 = "kRFcBgPVb = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "    bDKEnRnhPl = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s18 = "        UtebjgmLRkj = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "        zCzGWprWxj = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s20 = "    VSxTwv[uHITSbhI[donorI+1]](syPpqCjYM, 1, \"KfMdNGPHD\" === \"DowetXp\"); lGTWWO = \"  \\\"TAG\\\": function( nodeNameSelecto" ascii

  condition:
    uint16(0) == 0x4d50 and
    8 of them
}