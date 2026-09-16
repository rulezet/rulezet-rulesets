rule sig_20160315_837a4454187190b836b68c1ac12d6ada {
  meta:
    description = "datamaliciousorder - file 20160315_837a4454187190b836b68c1ac12d6ada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7656bfe9c7299775acaff5c5b6c87516ac2a48f9d68cdbf715e05ed718f14e8"

  strings:
    $s1  = "    OzArOyBg = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "\"+\"ct2\" + \".co\"+(\"strips\",\"yesterday\",\"anthology\",\"alluvial\",\"nflict\")+(\"ravages\",\"spies\",\"subjecting\",\"XM" ascii
    $s3  = "sanctify = SojgA[3 * 5 - 3 * 3].split(\"conflict\").join(\"\");" fullword ascii
    $s4  = "accountant = ((\"delayed\", \"passenger\", \"NcuGKNN\", \"scion\", \"pREwqhwl\") + \"XQQlBhCRecg\").proudly();" fullword ascii
    $s5  = "mdfQQEJ.onreadystatechange = function () {" fullword ascii
    $s6  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "    mdfQQEJ.open((\"humans\",\"volition\",\"G\")+\"ET\", (\"optics\",\"drought\",\"finding\",\"h\")+(\"epistolary\",\"chamois\"," ascii
    $s8  = "\"+\"//\"+\"cr\"+\"ed\"+\"it\"+\"wa\"+\"ll\"+\"et\"+(\"pertinent\",\"titled\",\"dedication\",\"beaux\",\".n\")+\"et/87y\"+\"g7\"" ascii
    $s9  = "String.prototype.proudly = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "        wMiAoSy = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s11 = "var GtmXzSrII = this[sanctify];" fullword ascii
    $s12 = "milBETIsrsN = \" filter: {\";" fullword ascii
    $s13 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s14 = "lsmjIVPy = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        wMiAoSy = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s16 = "        tKWVRrHcJN = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "        vrAiSF = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    OzArOyBg = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s19 = "    JSTuPfJvt[SojgA[misconceptionI+1]](irXuOO, 1, \"wpqbozWcD\" === \"VdVvypyxc\"); JveFD = \"  \\\"TAG\\\": function( nodeNameS" ascii
    $s20 = "} catch (wUYLKpvR) { };" fullword ascii

  condition:
    uint16(0) == 0x7870 and
    8 of them
}