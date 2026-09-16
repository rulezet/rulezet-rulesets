rule sig_20160315_e5567b910d1756147c79e4fbf3157567 {
  meta:
    description = "datamaliciousorder - file 20160315_e5567b910d1756147c79e4fbf3157567.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165e299a8aee03d99d0153ad0eddf03e5baff0467806909008387b7731135ee9"

  strings:
    $s1  = "    nbcYfxBSa.open((\"inroads\",\"ladle\",\"G\")+\"ET\", \"http:\"+(\"ungracious\",\"eyesight\",\"nixon\",\"//aroh\")+\"am.com\"" ascii
    $s2  = "    LAUUerC = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s3  = "nbcYfxBSa.onreadystatechange = function () {" fullword ascii
    $s4  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s5  = "String.prototype.manhattan = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "        NJKmiAs = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s7  = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s8  = "xe\", false);" fullword ascii
    $s9  = "var wPsDxIH = this[copyrights];" fullword ascii
    $s10 = "bQtAFNaspb = \" filter: {\";" fullword ascii
    $s11 = "store = ((\"refraction\", \"cavalcade\", \"raqHyYqD\", \"dissuade\", \"pVEgUclHiIg\") + \"fjivtY\").manhattan();" fullword ascii
    $s12 = "        NJKmiAs = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s13 = "ytMHqkn = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "        IjUmydbPVv = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s15 = "        RQLDnnOYqbq = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s16 = "    LAUUerC = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s17 = "    cUeNvUVaE[xBTuLXsQx[puddleI+1]](JNGexE, 1, \"nIBaXIdcNWU\" === \"VBJaXF\"); NKjGEP = \"  \\\"TAG\\\": function( nodeNameSele" ascii
    $s18 = "} catch (nDLSr) { };" fullword ascii

  condition:
    uint16(0) == 0x4250 and
    8 of them
}