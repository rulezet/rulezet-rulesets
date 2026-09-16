rule sig_20160315_c7b88cb8091fed13ceafc42a845e059d {
  meta:
    description = "datamaliciousorder - file 20160315_c7b88cb8091fed13ceafc42a845e059d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c066197a65c57bba5e1507d218afdb3d2b35c93a8e35a45b80f2752d88b6f7c3"

  strings:
    $s1  = "    CpfXOpB = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "isolate = mTDWk[3 * 5 - 3 * 3].split(\"fears\").join(\"\");" fullword ascii
    $s3  = "vzJYds.onreadystatechange = function () {" fullword ascii
    $s4  = "= +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "    vzJYds.open(\"G\"+(\"producer\",\"banking\",\"ET\"), \"h\"+\"tt\"+\"p:\"+(\"easier\",\"douglas\",\"lottery\",\"//\")+\"gl\"+" ascii
    $s6  = "heavy = ((\"david\", \"shaping\", \"fCiHqT\", \"birmingham\", \"pIETFUJW\") + \"hqoGLK\").input();" fullword ascii
    $s7  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.input = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        fURQAEwYIB = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s10 = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s11 = "zzle.error( match[0] );     \";" fullword ascii
    $s12 = "var WGYTX = this[isolate];" fullword ascii
    $s13 = "/87\"+\"yg\"+\"75\"+(\"erosion\",\"hometown\",\"associated\",\"names\",\"6f\")+(\"literati\",\"twist\",\"5.\")+\"exe\", false);" fullword ascii
    $s14 = "ndjjBRncoTn = \" filter: {\";" fullword ascii
    $s15 = "    match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );     m" ascii
    $s16 = "ERvaTIaA = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "        fURQAEwYIB = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s18 = "        qbdaKnTy = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    CpfXOpB = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s20 = "        oPnesgAxV = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii

  condition:
    uint16(0) == 0x514f and
    8 of them
}