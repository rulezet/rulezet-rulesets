rule sig_20160321_1273237cfc5ec0d0c7a419141af1c468 {
  meta:
    description = "datamaliciousorder - file 20160321_1273237cfc5ec0d0c7a419141af1c468.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e87ec9a9ffa4ea946437145b2dd736823d7694b02ed47fc27795bc17e9822e8c"

  strings:
    $s1  = "endurable(\"http:\"+\"//tr\"+\"avel\"+(\"basis\",\"opponents\",\"presentable\",\"re\")+\"vi\"+\"ew24\"+\"7.com/\"+\"89h7\"+\"66" ascii
    $s2  = "ngth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relat" ascii
    $s3  = "   ybLxlmdg = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.l" ascii
    $s4  = "    SpPvji = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s5  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s6  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s7  = "DcbrhS = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "DcbrhS = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s10 = "Pycxwm = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s11 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s12 = "        gPvcRcLWY[Idfulos[titlesI + 1]](attempted, 1, \"PgLDKMf\" === \"BpoaaJkr\"); kljOV = \" Precompiled matchers will still " ascii
    $s13 = "        bvyVfTn = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s14 = "        gPvcRcLWY[Idfulos[titlesI + 1]](attempted, 1, \"PgLDKMf\" === \"BpoaaJkr\"); kljOV = \" Precompiled matchers will still " ascii
    $s15 = "        var attempted = LrREz + \"/\" + lovely + Idfulos[titlesI];" fullword ascii
    $s16 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s17 = "        PxDdRNR[(protoplasm + \"o\"+(\"astrology\",\"thanksgiving\",\"lukewarm\",\"Di\")+(\"alternatives\",\"probity\",\"ti\")+" ascii
    $s18 = "        PxDdRNR[(protoplasm + \"o\"+(\"astrology\",\"thanksgiving\",\"lukewarm\",\"Di\")+(\"alternatives\",\"probity\",\"ti\")+" ascii
    $s19 = "y ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "String.prototype.packs = function () { return this.substr(0, 1); };" fullword ascii

  condition:
    uint16(0) == 0x5842 and
    8 of them
}