rule sig_20160321_97c87e3f808ce13e56519aa2df6e0487 {
  meta:
    description = "datamaliciousorder - file 20160321_97c87e3f808ce13e56519aa2df6e0487.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c615e32b86ae0d577fb06b76c0f4c823432d14d3118c83482d0e3fddf49342c1"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "   vGRlKXnfzlN = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s3  = "    ePeKUUhY = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "detriment(\"h\"+\"ttp:\"+\"//vy\"+\"veon.c\"+(\"except\",\"casino\",\"pulled\",\"thatch\",\"om\")+\"/wp-co\"+\"nten\"+\"t/pl\"+" ascii
    $s8  = "wVAwFmLcj = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "wVAwFmLcj = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s10 = "dqcmXggqEIq = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s11 = "        AAoGmxkBN = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii
    $s12 = "function detriment(apologize, testament) {" fullword ascii
    $s13 = "appening\",\"surrounded\",\"nettle\",\"T\"), apologize, false);" fullword ascii
    $s14 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s15 = "    GSntycqLs[\"o\" + smoldering + branchese + \"n\"]((\"northern\",\"finding\",\"selective\",\"strongly\",\"G\") + branchese + " ascii
    $s16 = "h ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ exp" ascii
    $s17 = "cestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s19 = "dqcmXggqEIq = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s20 = "String.prototype.warrant = function () { return this.substr(0, 1); };" fullword ascii

  condition:
    uint16(0) == 0x6666 and
    8 of them
}