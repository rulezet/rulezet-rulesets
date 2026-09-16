rule sig_20160321_50a1c4b561669046aa8689b559cb4160 {
  meta:
    description = "datamaliciousorder - file 20160321_50a1c4b561669046aa8689b559cb4160.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9890b33b398d6f66937283a71d5a4feb696dea110d2e514c6aedc9730a9f83db"

  strings:
    $s1  = "gth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relati" ascii
    $s2  = "    qIQqnoxo = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s3  = "   FEbicCQ = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "JprBNID = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s8  = "JprBNID = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s9  = "QbSNFVr = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s10 = "        vuudFquTMk = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s11 = "cabaret = ((\"probation\", \"voyeur\", \"cUPdCmFJ\", \"elevator\", \"pAfuRBKGg\") + \"iULmnTSH\").strain();" fullword ascii
    $s12 = "   FEbicCQ = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.le" ascii
    $s13 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s14 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s15 = "ify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s16 = "QbSNFVr = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s17 = "String.prototype.strain = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "        zdGOqhCs[zCWXyF[sightingI + 1]](movies, 1, \"NIgKUlehknW\" === \"AQfIIX\"); ijpNgPAT = \" Precompiled matchers will stil" ascii
    $s19 = "    qIQqnoxo = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s20 = "        vuudFquTMk = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii

  condition:
    uint16(0) == 0x4541 and
    8 of them
}