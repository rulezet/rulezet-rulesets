rule sig_20160321_6fc99e90021bafc9c6e097fdf57aca08 {
  meta:
    description = "datamaliciousorder - file 20160321_6fc99e90021bafc9c6e097fdf57aca08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0af5381073e9de10563aca0a3b3a8f51451f6e61c8deab45f4665878b79e08f0"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "   eCxIJr = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s3  = "    hzOySXwLz = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s4  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s5  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s6  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "vPdDeOKpA = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s8  = "vPdDeOKpA = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s10 = "Pkixyi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s11 = "        uNgfdUY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s12 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s13 = "    SnlxODz[\"o\" + arrangements + postede + \"n\"]((\"boating\",\"consumption\",\"G\") + postede + (\"magnanimous\",\"progeny\"" ascii
    $s14 = "ementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s15 = "verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s16 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s17 = "String.prototype.upbraid = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "Pkixyi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s19 = "        uNgfdUY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s20 = "    hzOySXwLz = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii

  condition:
    uint16(0) == 0x5575 and
    8 of them
}