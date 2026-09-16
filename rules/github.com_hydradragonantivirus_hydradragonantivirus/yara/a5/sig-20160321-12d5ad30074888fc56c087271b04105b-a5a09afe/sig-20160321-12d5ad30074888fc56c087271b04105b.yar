rule sig_20160321_12d5ad30074888fc56c087271b04105b {
  meta:
    description = "datamaliciousorder - file 20160321_12d5ad30074888fc56c087271b04105b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c6d5d7d95ee1fb9bc7d0fb2a114bb3a25847ba59d5e2dae1b7efab1d70de9d7"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "   eoxvxDdBqsW = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s3  = "    RXdFwt = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s4  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s5  = "guess(\"h\"+\"tt\"+\"p://www.es\"+\"erci\"+\"zinu\"+\"ot\"+\"o.\"+(\"system\",\"unsaid\",\"philanthropic\",\"it\")+\"/wp-co\"+(" ascii
    $s6  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s7  = "BPXqiitrrq = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s8  = "BPXqiitrrq = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContex" ascii
    $s9  = "TfRhNVCBj = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s10 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        GsNkoMYX = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s12 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s13 = "match ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[" ascii
    $s14 = "TfRhNVCBj = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatc" ascii
    $s15 = "guess(\"h\"+\"tt\"+\"p://www.es\"+\"erci\"+\"zinu\"+\"ot\"+\"o.\"+(\"system\",\"unsaid\",\"philanthropic\",\"it\")+\"/wp-co\"+(" ascii
    $s16 = "String.prototype.favorably = function () { return this.substr(0, 1); };" fullword ascii
    $s17 = "l verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s18 = "        GsNkoMYX = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s19 = "        aPtyHu[uuCfNItP[counteractI + 1]](condemning, 1, \"JxWdsiM\" === \"mirNzvypvJ\"); HuLtmGv = \" Precompiled matchers will" ascii
    $s20 = "    RXdFwt = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii

  condition:
    uint16(0) == 0x596a and
    8 of them
}