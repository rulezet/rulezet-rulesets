rule sig_20160321_8b1c61f6503cc8afc6032042d821520b {
  meta:
    description = "datamaliciousorder - file 20160321_8b1c61f6503cc8afc6032042d821520b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de6162fef358a5f9eaaeae0c0a308f1bd4701015b6b293b56d2b8da1169e475d"

  strings:
    $s1  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s2  = "    YjnOTC = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s3  = "   EVBOKy = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s4  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s5  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s6  = "venerate = ((\"ecuador\", \"clink\", \"vHbIrAGv\", \"worthy\", \"pQnIGbmhWNvs\") + \"mpspygyh\").indiscreet();" fullword ascii
    $s7  = "wxtzTr = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "wxtzTr = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "AOVhknSQg = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s10 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        OgeYuxJdyj = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s12 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s13 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s14 = "cestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii
    $s16 = "invention(\"h\"+\"ttp://\"+(\"lateness\",\"crayon\",\"quality\",\"abortion\",\"spor\")+\"mixariza.c\"+(\"johnson\",\"partner\"," ascii
    $s17 = "String.prototype.indiscreet = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "AOVhknSQg = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s19 = "        yNqllDs[lioahW[glandI + 1]](indiscreet, 1, \"xOwvmQL\" === \"egmVVi\"); VyhgIh = \" Precompiled matchers will still veri" ascii
    $s20 = "        yNqllDs[lioahW[glandI + 1]](indiscreet, 1, \"xOwvmQL\" === \"egmVVi\"); VyhgIh = \" Precompiled matchers will still veri" ascii

  condition:
    uint16(0) == 0x534f and
    8 of them
}