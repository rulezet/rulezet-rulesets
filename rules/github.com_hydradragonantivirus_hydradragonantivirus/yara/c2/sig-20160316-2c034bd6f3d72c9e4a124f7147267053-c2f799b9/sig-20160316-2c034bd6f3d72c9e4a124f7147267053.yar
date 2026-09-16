rule sig_20160316_2c034bd6f3d72c9e4a124f7147267053 {
  meta:
    description = "datamaliciousorder - file 20160316_2c034bd6f3d72c9e4a124f7147267053.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dffcb483d62a94aa64df2d39abc59bf3fdfa6c556ee0d8c7231f815501fdd972"

  strings:
    $s1  = "ments\",\"St\")+\"ri\"+(\"thermal\",\"seville\",\"playlist\",\"ngs\"), \"\"+(\"purpose\",\"harem\",\"pedagogue\",\"brabant\",\"%" ascii
    $s2  = "BYqGll.onreadystatechange = function () {" fullword ascii
    $s3  = " || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "    icEna[FbqtDU[difficultyI+1]](PTMkPBK, 1, \"UtMzHuLUM\" === \"WMNWuenV\"); iEJgId = \" \\\"PSEUDO\\\": function( pseudo, argu" ascii
    $s5  = "undertone = ((\"drink\", \"roguish\", \"zqRqAwW\", \"reviewed\", \"pBBjLoPCjq\") + \"UkzFKRjxn\").angela();" fullword ascii
    $s6  = "JRAkpHP = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s7  = "toFLPei = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "UoCcaDgS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s9  = "String.prototype.angela = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "KEXbXE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s11 = "pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cust" ascii
    $s12 = "KEXbXE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "y\",\"eliminated\",\"dominican\",\"on\")+(\"sufficient\",\"places\",\"bologna\",\"me\")+(\"steve\",\"macaroni\",\"nt\")+(\"abash" ascii
    $s14 = "    BYqGll.open(\"G\"+(\"witch\",\"confluence\",\"monaco\",\"stephanie\",\"ET\"), (\"beacon\",\"jerkin\",\"incandescent\",\"broa" ascii
    $s15 = "UoCcaDgS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s16 = "iedivstra\")+\"ti\"+\"fi\"+\"edeXst\"+\"rati\"+(\"claimed\",\"unconvinced\",\"fiedOb\")+(\"ellipse\",\"stretch\",\"depreciate\"," ascii
    $s17 = "thong = FbqtDU[2+2+2].split(\"stratified\").join(\"\");" fullword ascii
    $s18 = "\",\"teach\",\"5g\")+\"45\"+\"hg\"+\".e\"+(\"abbreviations\",\"gamut\",\"xe\"), false);" fullword ascii
    $s19 = "var RtTBcM = this[thong];" fullword ascii
    $s20 = "ied\"+\"MLst\"+(\"melodramatic\",\"disagreed\",\"cataract\",\"rati\")+(\"verbal\",\"fetching\",\"walks\",\"craven\",\"fied2\") +" ascii

  condition:
    uint16(0) == 0x4f4e and
    8 of them
}