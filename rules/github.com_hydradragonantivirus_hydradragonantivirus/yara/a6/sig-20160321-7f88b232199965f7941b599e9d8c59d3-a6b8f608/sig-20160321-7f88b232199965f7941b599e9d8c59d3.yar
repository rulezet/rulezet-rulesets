rule sig_20160321_7f88b232199965f7941b599e9d8c59d3 {
  meta:
    description = "datamaliciousorder - file 20160321_7f88b232199965f7941b599e9d8c59d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8b5a2a2d14f5d816112c7d533df4bcc6532cc6ca2e0500d7da5fd089b9e1925"

  strings:
    $s1  = "rudimentary(\"h\"+(\"hygienic\",\"biographical\",\"police\",\"ttp:\")+(\"ownership\",\"booty\",\"jocose\",\"executed\",\"//\")+(" ascii
    $s2  = "length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rel" ascii
    $s3  = "   SusXJXulJC = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens" ascii
    $s4  = "    nHXbisCbkJ = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Stri" ascii
    $s5  = "rudimentary(\"h\"+(\"hygienic\",\"biographical\",\"police\",\"ttp:\")+(\"ownership\",\"booty\",\"jocose\",\"executed\",\"//\")+(" ascii
    $s6  = "Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @para" ascii
    $s7  = "ed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "ontext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match =" ascii
    $s9  = "KnacbaBIxz = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s10 = "KnacbaBIxz = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s11 = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s12 = "YjGYKY = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s13 = "    vJmWiJE[sources + (\"worldliness\",\"unauthorized\",\"leaflet\",\"e\") + ((\"erotic\", \"crucifix\", \"OFQReRRGLvp\", \"phys" ascii
    $s14 = "        XMqFvfri = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s15 = "String.prototype.portraiture = function () { return this.substr(0, 1); };" fullword ascii
    $s16 = "\", \"neBShbKxD\") + \"XfVQeInTjcT\").portraiture() + ((\"assassinate\", \"reads\", \"LiurAyi\", \"mosaic\", \"advocacy\", \"ddh" ascii
    $s17 = "m {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, c" ascii
    $s18 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii
    $s19 = "ll verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "writhe = ((\"regard\", \"massage\", \"FguTrz\", \"calculus\", \"pMCjEDG\") + \"qPfjjDjkMR\").portraiture();" fullword ascii

  condition:
    uint16(0) == 0x7742 and
    8 of them
}