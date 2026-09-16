rule sig_20160321_8893281e499ce0eea1e04c4f92523026 {
  meta:
    description = "datamaliciousorder - file 20160321_8893281e499ce0eea1e04c4f92523026.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d32141e0c394dae6fb24193c8d6429ed88acc863738860ad38da7a7f6e2a8d5c"

  strings:
    $s1  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s2  = "    UeDbHRemB = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s3  = "   xJMgSGE = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s4  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s5  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s6  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "BcBXGQ = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "BcBXGQ = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "ksowFndQXu = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s10 = "        UiJpRRlthk = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s11 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s12 = "   xJMgSGE = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s13 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s14 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii
    $s15 = "ksowFndQXu = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s16 = "String.prototype.hawthorn = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "fy ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "    UeDbHRemB = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s19 = "        taDtzfycJ[JTCoTJw[actualI + 1]](rectum, 1, \"GCSSqIYRBrM\" === \"vajDNRkH\"); aLJXv = \" Precompiled matchers will still" ascii
    $s20 = "        UiJpRRlthk = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii

  condition:
    uint16(0) == 0x7266 and
    8 of them
}