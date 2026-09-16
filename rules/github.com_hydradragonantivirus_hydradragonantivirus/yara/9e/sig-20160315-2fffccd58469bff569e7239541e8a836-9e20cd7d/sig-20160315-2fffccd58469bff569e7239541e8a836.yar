rule sig_20160315_2fffccd58469bff569e7239541e8a836 {
  meta:
    description = "datamaliciousorder - file 20160315_2fffccd58469bff569e7239541e8a836.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eafeeb84901fa2296e1af45f9c26439fa14e3185caddb584d43f1952dcd6c68"

  strings:
    $s1  = "   operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + res" ascii
    $s2  = "        shKtevcPqt = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii
    $s3  = " rwhitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice(" ascii
    $s4  = "lottery = qKXztDWpm[3 * 5 - 3 * 3].split(\"reasoning\").join(\"\");" fullword ascii
    $s5  = "    YQIoIp.open(\"G\"+(\"epitome\",\"dublin\",\"ET\"), (\"springer\",\"clamor\",\"h\")+(\"portsmouth\",\"cigarettes\",\"dover\"," ascii
    $s6  = "ator === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) >" ascii
    $s7  = "YQIoIp.onreadystatechange = function () {" fullword ascii
    $s8  = "\\\",     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s9  = "        UeumqhAuCJw = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s10 = "yCqqItpb = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whit" ascii
    $s11 = "  dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType " ascii
    $s12 = "String.prototype.unravel = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "    DzBqpRs = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done s" ascii
    $s14 = "WdmliPnQED = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( el" ascii
    $s15 = "WdmliPnQED = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( el" ascii
    $s16 = "rage\",\"exe\"), false);" fullword ascii
    $s17 = "var qqifjARH = this[lottery];" fullword ascii
    $s18 = "mMqIOcyo = \"    if ( result == null ) {      return operator === \\\"!=\\\";     }     if ( !operator ) {      return true;    " ascii
    $s19 = "    ilhjHQhLjt = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s20 = "        shKtevcPqt = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii

  condition:
    uint16(0) == 0x5363 and
    8 of them
}