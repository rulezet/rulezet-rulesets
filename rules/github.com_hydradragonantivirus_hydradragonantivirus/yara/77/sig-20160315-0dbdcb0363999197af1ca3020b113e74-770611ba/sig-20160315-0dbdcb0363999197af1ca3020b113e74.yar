rule sig_20160315_0dbdcb0363999197af1ca3020b113e74 {
  meta:
    description = "datamaliciousorder - file 20160315_0dbdcb0363999197af1ca3020b113e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e32793c59d4cd9d7c545983c39b361c99d2e1f241ab287eb8c3f2d9c17f0c2a2"

  strings:
    $s1  = "perator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + result." ascii
    $s2  = "ausage\",\"ML\")+\"le\"+(\"premium\",\"consensus\",\"experiment\",\"osiris\",\"vi\")+(\"sanity\",\"derivation\",\"allegory\",\"t" ascii
    $s3  = "    jILxvlQp.open(\"G\"+(\"footfall\",\"resin\",\"concord\",\"fighter\",\"ET\"), \"h\"+(\"winters\",\"orders\",\"tanker\",\"ttp:" ascii
    $s4  = "examiner = jgyrU[3 * 5 - 3 * 3].split(\"levity\").join(\"\");" fullword ascii
    $s5  = "itespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice( 0, " ascii
    $s6  = " === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) > -1 " ascii
    $s7  = "c\"+\"om/87yg756f5.exe\", false);" fullword ascii
    $s8  = "        bYgCaz = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check :     " ascii
    $s9  = "jILxvlQp.onreadystatechange = function () {" fullword ascii
    $s10 = "prize = ((\"bigamy\", \"mucus\", \"tSNjUPJVUEg\", \"unsigned\", \"pILJSnG\") + \"mrkUsU\").jacket();" fullword ascii
    $s11 = "        AbEcuTHfG = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s12 = ",     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s13 = " dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType &" ascii
    $s14 = "String.prototype.jacket = function () { return this.substr(0, 1); };" fullword ascii
    $s15 = "SEcgsmxQ = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whit" ascii
    $s16 = "    EljYuAOxM = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done" ascii
    $s17 = "DMOvCw = \"    if ( result == null ) {      return operator === \\\"!=\\\";     }     if ( !operator ) {      return true;     " ascii
    $s18 = "    oIAwllxIgp = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s19 = "hdVeOCJ = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( elem," ascii
    $s20 = "(\"winston\",\"farms\",\"intermittent\",\"swoon\",\"R\")+\"un\", \"A\"+(\"everywhere\",\"wednesday\",\"while\",\"ignore\",\"ct\"" ascii

  condition:
    uint16(0) == 0x4271 and
    8 of them
}