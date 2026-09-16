rule sig_20160321_b4cb4257c00efdc4fe3cd3b35f103a4d {
  meta:
    description = "datamaliciousorder - file 20160321_b4cb4257c00efdc4fe3cd3b35f103a4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bc58d1b708b3b6efa884377ffb5f38d55469400bccce9802b3290041548f579"

  strings:
    $s1  = "nudity(\"http://\"+\"batdon\"+(\"seats\",\"cooperative\",\"expressions\",\"fiddling\",\"gsan\")+(\"wally\",\"tours\",\"dissuade" ascii
    $s2  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s3  = "    kxpsxc = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s4  = "   IyVdVC = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s5  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s6  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s7  = "nudity(\"http://\"+\"batdon\"+(\"seats\",\"cooperative\",\"expressions\",\"fiddling\",\"gsan\")+(\"wally\",\"tours\",\"dissuade" ascii
    $s8  = "hgPcsBRAH = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s9  = "hgPcsBRAH = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s10 = "FQYdNsjj = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s11 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s12 = "        bxQEFzM = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s13 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s14 = "retrospect = ((\"legitimate\", \"appointments\", \"lxwdiFFVnDf\", \"asset\", \"paxtKejXLPas\") + \"jVVxXDYPc\").erosion();" fullword ascii
    $s15 = "y ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s16 = "ementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s17 = "tch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ e" ascii
    $s18 = "String.prototype.erosion = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "FQYdNsjj = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s20 = "        XlduPtegY[(retrospect + \"o\"+\"Di\"+(\"flights\",\"mediawiki\",\"ti\")+(\"ceiling\",\"passing\",\"servers\",\"uninhabit" ascii

  condition:
    uint16(0) == 0x4570 and
    8 of them
}