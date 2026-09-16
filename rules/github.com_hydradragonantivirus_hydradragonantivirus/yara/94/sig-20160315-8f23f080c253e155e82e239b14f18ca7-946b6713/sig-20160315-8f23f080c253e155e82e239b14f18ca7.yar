rule sig_20160315_8f23f080c253e155e82e239b14f18ca7 {
  meta:
    description = "datamaliciousorder - file 20160315_8f23f080c253e155e82e239b14f18ca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd82de2f1d09321deb44cfbde3c7509e6a421d9d7d8b2c5d0060e52e2f35ad76"

  strings:
    $s1  = "    EjrDKFlStF = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "desecration = IxKGmARbw[3 * 5 - 3 * 3].split(\"knickerbockers\").join(\"\");" fullword ascii
    $s3  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s4  = "fBIPCKMLv.onreadystatechange = function () {" fullword ascii
    $s5  = "[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "    fBIPCKMLv.open(\"G\"+(\"magic\",\"breastwork\",\"pound\",\"ET\"), (\"furthermore\",\"results\",\"artifice\",\"h\")+\"ttp:\"+" ascii
    $s7  = "currently = ((\"elation\", \"hopping\", \"evivKvbLRO\", \"absently\", \"pYgqdfue\") + \"xxhRPoMB\").inaugurate();" fullword ascii
    $s8  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = ",\"pursuant\",\"consolidated\",\"threshold\",\"rselkn\")+(\"incident\",\"versions\",\"ickerb\")+(\"encoding\",\"restructuring\"," ascii
    $s10 = "merican\",\"egregious\",\"g7\")+\"56f5.exe\", false);" fullword ascii
    $s11 = "String.prototype.inaugurate = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "        cNPnbOy = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s13 = "var NIKHgD = this[desecration];" fullword ascii
    $s14 = "I\")+(\"mount\",\"kelly\",\"zo\")+\"vx\", \"Exp\"+\"andE\"+\"nvir\"+\"on\"+\"mentSt\"+\"ri\"+(\"turban\",\"roofed\",\"rebuilt\"," ascii
    $s15 = "GcIRviM = \" filter: {\";" fullword ascii
    $s16 = "0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );  " ascii
    $s17 = "UclOUfJB = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = "        cNPnbOy = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s19 = "        lDiqaxbLQ = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s20 = "        GRXuwn = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}