rule sig_20160321_0c1ddcd0ddccb625b7534d11438f46d0 {
  meta:
    description = "datamaliciousorder - file 20160321_0c1ddcd0ddccb625b7534d11438f46d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b42e87a902d2b38836366abb935e1963ea520de8bfee8cc9047f1315be0c28f"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "   UCsDUm = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s3  = "    jrVBOJH = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s4  = "stepfather((\"hazards\",\"carboniferous\",\"h\")+(\"sherry\",\"regarding\",\"ttp://dichvu\")+(\"budgets\",\"moisten\",\"collater" ascii
    $s5  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s6  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s7  = "ePUbRu = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "ePUbRu = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "cfCsGFWIv = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s10 = "        ghDhnabYgO = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s11 = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s12 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s13 = "match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[" ascii
    $s14 = " verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "String.prototype.abstracted = function () { return this.substr(0, 1); };" fullword ascii
    $s16 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s17 = "cfCsGFWIv = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s18 = "    jrVBOJH = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s19 = "        dgAtFef[FpbtNER[stagnantI + 1]](liberated, 1, \"YBUQSxENp\" === \"ykYtaRlWxB\"); VNIptXT = \" Precompiled matchers will " ascii
    $s20 = "        dgAtFef[FpbtNER[stagnantI + 1]](liberated, 1, \"YBUQSxENp\" === \"ykYtaRlWxB\"); VNIptXT = \" Precompiled matchers will " ascii

  condition:
    uint16(0) == 0x5861 and
    8 of them
}