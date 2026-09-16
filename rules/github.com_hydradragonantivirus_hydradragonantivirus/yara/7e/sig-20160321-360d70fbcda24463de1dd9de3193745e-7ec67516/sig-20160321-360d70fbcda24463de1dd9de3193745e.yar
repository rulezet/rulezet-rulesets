rule sig_20160321_360d70fbcda24463de1dd9de3193745e {
  meta:
    description = "datamaliciousorder - file 20160321_360d70fbcda24463de1dd9de3193745e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f673013b1ad6c7b0723f8a56946e7adde39faf7264b0f7e2424e9c093d1b502"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "    GczALtR = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s3  = "   nssMHMtbtYX = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s4  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s5  = "tempestuous = ((\"respiratory\", \"brimstone\", \"CImKem\", \"normally\", \"pfWdHOW\") + \"xBnMalYYM\").lincolnshire();" fullword ascii
    $s6  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s7  = "LdmIgD = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "LdmIgD = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s10 = "jVgOlG = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s11 = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s12 = "        eoqFoqhL = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s13 = "        dgXkdtM[(tempestuous + \"o\"+\"Di\"+\"ti\"+(\"offered\",\"august\",\"guild\",\"ethan\",\"on\")).replace(\"D\", grahams)]" ascii
    $s14 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s15 = "tch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ e" ascii
    $s16 = "String.prototype.lincolnshire = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "jVgOlG = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s18 = " ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s19 = "        VxpcWQ[idLMIT[similarlyI + 1]](affair, 1, \"gRmCETuVA\" === \"WASvLTO\"); tFVEsRA = \" Precompiled matchers will still v" ascii
    $s20 = "    uBHCwVIA[\"o\" + tempestuous + cassandrae + \"n\"]((\"throughout\",\"redden\",\"theoretical\",\"G\") + cassandrae + (\"brook" ascii

  condition:
    uint16(0) == 0x6a55 and
    8 of them
}