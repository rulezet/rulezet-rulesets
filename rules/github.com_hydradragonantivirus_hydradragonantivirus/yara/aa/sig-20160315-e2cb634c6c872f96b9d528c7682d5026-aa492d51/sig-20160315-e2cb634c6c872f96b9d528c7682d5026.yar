rule sig_20160315_e2cb634c6c872f96b9d528c7682d5026 {
  meta:
    description = "datamaliciousorder - file 20160315_e2cb634c6c872f96b9d528c7682d5026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75c09034faab091a619cb5a6465a7eca0014f0dfc08ec63d080e750f5de12509"

  strings:
    $s1  = "    vuwdeLGw = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "invasion = PHoQck[3 * 5 - 3 * 3].split(\"pajamas\").join(\"\");" fullword ascii
    $s3  = "f5.exe\", false);" fullword ascii
    $s4  = "SvxuzRbXU.onreadystatechange = function () {" fullword ascii
    $s5  = "    SvxuzRbXU.open(\"G\"+(\"consuming\",\"protestant\",\"ET\"), (\"fraud\",\"inter\",\"puppies\",\"bacteria\",\"http://hppl\")+" ascii
    $s6  = "[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "withering = ((\"northwest\", \"generates\", \"hfQPawDl\", \"effrontery\", \"ptmLDpeLIQA\") + \"NXtWcTUQNd\").rules();" fullword ascii
    $s8  = "String.prototype.rules = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        aKmNqGfxGQ = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s10 = "zzle.error( match[0] );     \";" fullword ascii
    $s11 = "var NmVJGCW = this[invasion];" fullword ascii
    $s12 = "rqHFmNg = \" filter: {\";" fullword ascii
    $s13 = "0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );  " ascii
    $s14 = "        aKmNqGfxGQ = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s15 = "TiAhSyeydkl = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "        YTmTmhre = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = "        cLxXSF = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    vuwdeLGw = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s19 = "    fQGjFEF[PHoQck[academicalI+1]](JmBvsni, 1, \"LRhygLiIvWV\" === \"gWaIDbf\"); QkfBb = \"  \\\"TAG\\\": function( nodeNameSele" ascii
    $s20 = "} catch (AUkzd) { };" fullword ascii

  condition:
    uint16(0) == 0x5258 and
    8 of them
}