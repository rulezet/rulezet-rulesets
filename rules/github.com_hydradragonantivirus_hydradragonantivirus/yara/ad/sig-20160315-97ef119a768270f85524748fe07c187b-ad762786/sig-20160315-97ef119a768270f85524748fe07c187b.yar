rule sig_20160315_97ef119a768270f85524748fe07c187b {
  meta:
    description = "datamaliciousorder - file 20160315_97ef119a768270f85524748fe07c187b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e8de1839499093b705952eded9ba9d3d5a5b8f179a24e4166242726012c79ab"

  strings:
    $s1  = "    oXLNcqIo = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "patch = omMBFlDgo[3 * 5 - 3 * 3].split(\"crutch\").join(\"\");" fullword ascii
    $s3  = "fuTwQ.onreadystatechange = function () {" fullword ascii
    $s4  = "gradually = ((\"nitrogen\", \"somerset\", \"YArdjQf\", \"tableaux\", \"pAwRfBWiB\") + \"tjaLHx\").shorthand();" fullword ascii
    $s5  = "String.prototype.shorthand = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "        VaVRNupfXe = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s7  = "zzle.error( match[0] );     \";" fullword ascii
    $s8  = "var rgnJB = this[patch];" fullword ascii
    $s9  = "IjfhuPwLXKt = \" filter: {\";" fullword ascii
    $s10 = "\",\"necessary\",\"gross\",\"f5.e\")+(\"forensic\",\"airily\",\"persian\",\"xe\"), false);" fullword ascii
    $s11 = "LJxfIn = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s12 = "        VaVRNupfXe = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s13 = "        WeTxcDSnaX = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s14 = "        updHhQSbkF = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s15 = "    oXLNcqIo = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s16 = "    PLeTVAwcw[omMBFlDgo[loftinessI+1]](vaBPTegN, 1, \"NBpFGClYu\" === \"NdbHQSTzt\"); nmayGvD = \"  \\\"TAG\\\": function( nodeN" ascii
    $s17 = "    fuTwQ.open((\"strike\",\"decease\",\"G\")+\"ET\", \"h\"+\"ttp://newl\"+(\"meekness\",\"continuity\",\"ea\")+(\"basal\",\"com" ascii
    $s18 = "} catch (ogCmKvbi) { };" fullword ascii
    $s19 = "        var tTlyq = new rgnJB(((\"filtering\",\"barrier\",\"dialogue\",\"symbolical\",\"\")+\"A\"+\"pO\"+\"DB.\"+(\"premonition" ascii
    $s20 = "\")+(\"strictly\",\"expansion\",\"collegiate\",\"blond\",\"in\")+\"/87y\"+\"g7\"+(\"orleans\",\"clause\",\"canticle\",\"56\")+(" ascii

  condition:
    uint16(0) == 0x6764 and
    8 of them
}