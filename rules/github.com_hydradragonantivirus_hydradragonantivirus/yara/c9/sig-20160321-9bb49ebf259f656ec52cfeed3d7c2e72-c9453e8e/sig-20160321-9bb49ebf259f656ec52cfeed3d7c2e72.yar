rule sig_20160321_9bb49ebf259f656ec52cfeed3d7c2e72 {
  meta:
    description = "datamaliciousorder - file 20160321_9bb49ebf259f656ec52cfeed3d7c2e72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08cf0ad4badd5daba434194f1358541e728de5715671fe905a6ca50204291e87"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "   vHhGXX = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s3  = "    LnOPAeK = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s4  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s5  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s6  = "kwzznCGWRR = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s7  = "kwzznCGWRR = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s8  = "tAiSHRBcYS = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s9  = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s10 = "biographer((\"achieving\",\"emphasize\",\"rough\",\"tunes\",\"h\")+\"ttp:\"+\"//cide\"+(\"kabul\",\"leaks\",\"ac\")+\".m\"+\"x/" ascii
    $s11 = "        DapilibAR = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii
    $s12 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s13 = "match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[" ascii
    $s14 = "cestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "captious = ((\"parasite\", \"comeliness\", \"AwkfTIF\", \"cathay\", \"pyiXgBKvHn\") + \"fLeEzPsF\").showtimes();" fullword ascii
    $s17 = "String.prototype.showtimes = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "tAiSHRBcYS = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s19 = "biographer((\"achieving\",\"emphasize\",\"rough\",\"tunes\",\"h\")+\"ttp:\"+\"//cide\"+(\"kabul\",\"leaks\",\"ac\")+\".m\"+\"x/" ascii
    $s20 = "    LnOPAeK = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii

  condition:
    uint16(0) == 0x6a67 and
    8 of them
}