rule sig_20160315_bfa4036de76650e3334e823f23c97dc0 {
  meta:
    description = "datamaliciousorder - file 20160315_bfa4036de76650e3334e823f23c97dc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59e34f5d90f2b39f19c94e2c5bc5d01b64873126c777cca3fad431cfa297f2a0"

  strings:
    $s1  = "   operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + res" ascii
    $s2  = "        oeOgwCqUeB = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii
    $s3  = " rwhitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice(" ascii
    $s4  = "ator === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) >" ascii
    $s5  = "NBYeBhRDi.onreadystatechange = function () {" fullword ascii
    $s6  = "    NBYeBhRDi.open((\"beguile\",\"shoulder\",\"potential\",\"G\")+\"ET\", (\"implacable\",\"clothes\",\"vibration\",\"h\")+\"tt" ascii
    $s7  = ",     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s8  = "        uoINnvdJC = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s9  = " dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType &" ascii
    $s10 = "vMpbwbDu = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whit" ascii
    $s11 = "String.prototype.zoophilia = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "gs.\") + (\"feign\",\"route\",\"unalloyed\",\"promenade\",\"S\"), \"qLwKmTcd\", \"h\"+\"of\"+\"feri\"+\"ngse\"+\"lo\"+\"ff\"+\"e" ascii
    $s13 = "\")+\"onment\"+(\"hives\",\"quicksand\",\"St\")+\"rings\", \"\"+(\"committee\",\"obliterate\",\"%\")+\"TE\"+\"MP%\", \"/sueeuv\"" ascii
    $s14 = "    dBOKYO = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done so" ascii
    $s15 = "        oeOgwCqUeB = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii
    $s16 = "FdJgBW = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( elem, " ascii
    $s17 = "    TifmIOIzR = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s18 = "FdJgBW = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( elem, " ascii
    $s19 = "var PJrSpkfqr = this[inducing];" fullword ascii
    $s20 = "HQHRMcHGt = \"    if ( result == null ) {      return operator === \\\"!=\\\";     }     if ( !operator ) {      return true;   " ascii

  condition:
    uint16(0) == 0x6142 and
    8 of them
}