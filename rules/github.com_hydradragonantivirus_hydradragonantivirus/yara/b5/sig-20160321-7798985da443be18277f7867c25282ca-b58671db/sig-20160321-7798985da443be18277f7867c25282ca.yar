rule sig_20160321_7798985da443be18277f7867c25282ca {
  meta:
    description = "datamaliciousorder - file 20160321_7798985da443be18277f7867c25282ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78e7943fa24fe622ded6b1add3367b17a96ff2d794f1aba6d662ea8444aa01a6"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "   uIAAhsdzYHX = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s3  = "    UzCbolFiNQH = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s4  = "|Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @par" ascii
    $s5  = "context, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match " ascii
    $s6  = "eed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "QIYXWSfbyJv = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s8  = "QIYXWSfbyJv = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s9  = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s10 = "combustible = ((\"generations\", \"baptist\", \"gUCoNNCkQ\", \"tomahawk\", \"pXmKbHcCshm\") + \"ABQaYQCD\").potential();" fullword ascii
    $s11 = "kheUwO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s12 = "        eSNIXRUOxJU = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s13 = "daughter(\"htt\"+\"p:\"+\"//\"+\"tr\"+\"av\"+\"el\"+\"re\"+\"vi\"+\"ew\"+\"247.\"+\"co\"+\"m/\"+\"89\"+\"h766\"+(\"remonstrate\"" ascii
    $s14 = "daughter(\"htt\"+\"p:\"+\"//\"+\"tr\"+\"av\"+\"el\"+\"re\"+\"vi\"+\"ew\"+\"247.\"+\"co\"+\"m/\"+\"89\"+\"h766\"+(\"remonstrate\"" ascii
    $s15 = "am {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, " ascii
    $s16 = " verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s17 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s18 = "String.prototype.potential = function () { return this.substr(0, 1); };" fullword ascii
    $s19 = "kheUwO = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s20 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii

  condition:
    uint16(0) == 0x7672 and
    8 of them
}