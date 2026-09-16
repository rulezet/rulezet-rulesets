rule sig_20160315_d37c16c4c1e60851e02724c5273c93c8 {
  meta:
    description = "datamaliciousorder - file 20160315_d37c16c4c1e60851e02724c5273c93c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b56fd3b86c9e6a367b5cb1182736e46114355deff81ead79d04f8987ff1d6bae"

  strings:
    $s1  = "\"tt\")+\"p:\"+\"//\"+\"hp\"+\"pl.net\"+(\"dorado\",\"houses\",\"democrat\",\"immodest\",\"/87yg7\")+\"56\"+\"f5.e\"+\"xe\", fal" ascii
    $s2  = "        wODeQzXJuLM = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check :" ascii
    $s3  = "    operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + re" ascii
    $s4  = "    sRMLqxNx.open((\"knife\",\"quadrangle\",\"proposed\",\"interjection\",\"G\")+\"ET\", \"h\"+(\"onlooker\",\"albanian\",\"worr" ascii
    $s5  = "( rwhitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice" ascii
    $s6  = "rator === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) " ascii
    $s7  = "sRMLqxNx.onreadystatechange = function () {" fullword ascii
    $s8  = ",     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s9  = "medieval\",\"nrip\")+\"tp\"+\"ri\"+\"nc\"+\"et\"+\"on.\" + (\"tormentor\",\"victor\",\"piecemeal\",\"S\"), \"NxwEQB\", \"hpr\"+" ascii
    $s10 = "        WgTDjCNGu = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s11 = "swoon = ((\"happiness\", \"coined\", \"Sdlpha\", \"absented\", \"pHgguah\") + \"BbelUGuY\").slack();" fullword ascii
    $s12 = "  dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType " ascii
    $s13 = "AVcHlSCH = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whit" ascii
    $s14 = "XMprincet\"+(\"fawning\",\"indisputable\",\"controversy\",\"runner\",\"on\")+(\"lithuania\",\"choir\",\"insertion\",\"LHprin\")+" ascii
    $s15 = "String.prototype.slack = function () { return this.substr(0, 1); };" fullword ascii
    $s16 = "    mISjoYff = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done " ascii
    $s17 = "Type === 1 ) {\";" fullword ascii
    $s18 = "lack()]();" fullword ascii
    $s19 = "    TxlWske = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s20 = "zhOMpHEiJ = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( ele" ascii

  condition:
    uint16(0) == 0x664f and
    8 of them
}