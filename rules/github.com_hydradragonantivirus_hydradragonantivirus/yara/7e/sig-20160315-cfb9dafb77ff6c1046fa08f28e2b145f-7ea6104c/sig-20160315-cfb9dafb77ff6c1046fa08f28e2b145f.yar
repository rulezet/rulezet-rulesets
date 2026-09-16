rule sig_20160315_cfb9dafb77ff6c1046fa08f28e2b145f {
  meta:
    description = "datamaliciousorder - file 20160315_cfb9dafb77ff6c1046fa08f28e2b145f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c0370a08b48272ab5a777f6b9fe795ce46132a5aa11ed34ddab8715b5f6b80f"

  strings:
    $s1  = "    GrpsFVdLJcH = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&  " ascii
    $s2  = "unbelievable = XlMvmdRr[3 * 5 - 3 * 3].split(\"halves\").join(\"\");" fullword ascii
    $s3  = "    mNXFya.open(\"G\"+(\"jargon\",\"texan\",\"pellucid\",\"terrorism\",\"ET\"), \"h\"+(\"toilsome\",\"deride\",\"tt\")+\"p:\"+\"" ascii
    $s4  = "   Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthe" ascii
    $s5  = "mNXFya.onreadystatechange = function () {" fullword ascii
    $s6  = "5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "chess = ((\"collector\", \"grandee\", \"sWJenWKQD\", \"keenness\", \"pGxdxOC\") + \"weJNGpL\").saucy();" fullword ascii
    $s8  = "sis     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "String.prototype.saucy = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "        yXHfoiUqD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s11 = "zle.error( match[0] );     \";" fullword ascii
    $s12 = "ictum\",\"7y\")+\"g756\"+(\"diffs\",\"squeal\",\"blare\",\"tether\",\"f5\")+(\"billow\",\"ecological\",\".e\")+\"xe\", false);" fullword ascii
    $s13 = "var dlcfakYKb = this[unbelievable];" fullword ascii
    $s14 = "aCojjkku = \" filter: {\";" fullword ascii
    $s15 = "/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );   " ascii
    $s16 = "        yXHfoiUqD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s17 = "mTbmTj = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = "        lPgehArEhnO = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    GrpsFVdLJcH = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&  " ascii
    $s20 = "        bHOJNpi = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii

  condition:
    uint16(0) == 0x4e51 and
    8 of them
}