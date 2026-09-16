rule sig_20160321_e748436e851b9240d949cea929a287c9 {
  meta:
    description = "datamaliciousorder - file 20160321_e748436e851b9240d949cea929a287c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84cff09cc9f8e06e6629ff5e281c5e7acd495da613b20571749e126213a7aeb1"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "    KmmTUrPd = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s3  = "   CSWmorppHnm = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "nrSiBbbaJFO = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s8  = "nrSiBbbaJFO = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s9  = "liYWcYfwOk = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMat" ascii
    $s10 = "ecological(\"h\"+\"ttp:\"+\"//\"+(\"colleges\",\"party\",\"cideac\")+\".m\"+\"x/\"+\"wp-c\"+\"on\"+(\"wheresoever\",\"abolitioni" ascii
    $s11 = "ecological(\"h\"+\"ttp:\"+\"//\"+(\"colleges\",\"party\",\"cideac\")+\".m\"+\"x/\"+\"wp-c\"+\"on\"+(\"wheresoever\",\"abolitioni" ascii
    $s12 = "function ecological(circumcision, ireland) {" fullword ascii
    $s13 = "        IXxoau = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], el" ascii
    $s14 = "        var LNiddNd = new SjtSqv(((\"entered\",\"paddy\",\"\")+\"A\"+\"pO\"+\"DB.\" + \"\"+\"S\"+(\"cretaceous\",\"temporal\",\"" ascii
    $s15 = "ardly\",\"T\"), circumcision, false);" fullword ascii
    $s16 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s17 = "    lfYWubX[\"o\" + driving + wrestlere + \"n\"]((\"seems\",\"diego\",\"edict\",\"gloating\",\"G\") + wrestlere + (\"betting\"," ascii
    $s18 = "driving = ((\"parley\", \"boils\", \"KWRzRwNSrNK\", \"alaska\", \"pOexXxyvtP\") + \"AEhgbCJVdD\").lameness();" fullword ascii
    $s19 = "y ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "!match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached" ascii

  condition:
    uint16(0) == 0x6562 and
    8 of them
}