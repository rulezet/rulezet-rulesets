rule sig_20160315_e9500136b28db79c4bf212a8dec3cda4 {
  meta:
    description = "datamaliciousorder - file 20160315_e9500136b28db79c4bf212a8dec3cda4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de1ffc6e4b18eeea7011bd286666d3099f9a2258e475fda602a79664f41498bf"

  strings:
    $s1  = "    qTvqXbbCcSH = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&  " ascii
    $s2  = "    oDWLg.open((\"shotgun\",\"waken\",\"terrorists\",\"G\")+\"ET\", \"htt\"+\"p:\"+\"//\"+\"c001\"+\"45\"+\"6.aa\"+\"a.idid\"+\"" ascii
    $s3  = "thoroughness = Icjqs[3 * 5 - 3 * 3].split(\"joshua\").join(\"\");" fullword ascii
    $s4  = "   Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthe" ascii
    $s5  = "oDWLg.onreadystatechange = function () {" fullword ascii
    $s6  = "+\"/log\"+\"s/\"+\"87\"+(\"quilt\",\"tenaciously\",\"sorry\",\"yg75\")+\"6f\"+\"5.\"+\"exe\", false);" fullword ascii
    $s7  = "censor = ((\"israeli\", \"cobra\", \"KLIUwFl\", \"alleged\", \"pUaYQeE\") + \"OgKRdwfB\").alfonso();" fullword ascii
    $s8  = "sis     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "String.prototype.alfonso = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "        GorLMji = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s11 = "bCjwRyycjYX = \" filter: {\";" fullword ascii
    $s12 = "var wdyUpidLE = this[thoroughness];" fullword ascii
    $s13 = "qhHYUDFFkk = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "    oDWLg[craftsmans + (\"shorter\",\"increasingly\",\"bottle\",\"e\") + ((\"ostler\", \"accelerate\", \"GVInWyHyth\", \"rightha" ascii
    $s15 = "        GorLMji = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s16 = "        cWDSuFCX = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "        ylODjMXo = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    qTvqXbbCcSH = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&  " ascii
    $s19 = "    CJqSxL[Icjqs[imitatorI+1]](yOTOM, 1, \"lPIdEMFGP\" === \"hirWOoxNhI\"); QegnJiI = \"  \\\"TAG\\\": function( nodeNameSelecto" ascii
    $s20 = "} catch (hKSzz) { };" fullword ascii

  condition:
    uint16(0) == 0x747a and
    8 of them
}