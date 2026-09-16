rule sig_20160315_69377c2df0e1bb51ae90801056d5b1ea {
  meta:
    description = "datamaliciousorder - file 20160315_69377c2df0e1bb51ae90801056d5b1ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f189fc47a22d29bad648490a9719681f463ab4cd1043a47b0708949cc55e5a51"

  strings:
    $s1  = "    QjkYG.open((\"obdurate\",\"circuit\",\"hoarding\",\"budget\",\"G\")+\"ET\", \"htt\"+(\"motel\",\"irrelevant\",\"titled\",\"c" ascii
    $s2  = "    aQmNIX = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s3  = "princess = ((\"incomplete\", \"allison\", \"DBhNimLP\", \"analysts\", \"pBuTDkXUG\") + \"KTYXunKf\").sixtysix();" fullword ascii
    $s4  = "//hppl.n\"+(\"employers\",\"undiscovered\",\"trigger\",\"functioning\",\"et/87yg756f5.exe\"), false);" fullword ascii
    $s5  = "QjkYG.onreadystatechange = function () {" fullword ascii
    $s6  = "   (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.sixtysix = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "        kwslGnUsHh = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s9  = "t excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis  " ascii
    $s10 = "zzle.error( match[0] );     \";" fullword ascii
    $s11 = "var pGhfXQE = this[arrears];" fullword ascii
    $s12 = "TjQzIwOw = \" filter: {\";" fullword ascii
    $s13 = "UQBBPqugdl = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        kwslGnUsHh = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s15 = "        fmYpyWDayO = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s16 = "        vomFcy = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "    aQmNIX = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s18 = "    GXyUzf[emdDEMDHq[upholsteryI+1]](ReLHzYn, 1, \"wCPrGe\" === \"OJWaAABfUs\"); CqUMR = \"  \\\"TAG\\\": function( nodeNameSele" ascii
    $s19 = "} catch (NHdRByNfx) { };" fullword ascii

  condition:
    uint16(0) == 0x4b59 and
    8 of them
}