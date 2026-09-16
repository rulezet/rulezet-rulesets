rule sig_20160321_a9cb6bd3e39e4dd1504767b398326c42 {
  meta:
    description = "datamaliciousorder - file 20160321_a9cb6bd3e39e4dd1504767b398326c42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81873718c81caa8ea1a1c1c97e3cdbd5f8290697e28091302b35cc05f51c7767"

  strings:
    $s1  = "albumen((\"jordan\",\"whiting\",\"h\")+(\"belgrade\",\"thong\",\"tt\")+(\"soulless\",\"inadvertently\",\"focused\",\"dresser\"," ascii
    $s2  = "ngth > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relat" ascii
    $s3  = "   XOltOlJo = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.l" ascii
    $s4  = "    kaWWQBq = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|" ascii
    $s5  = "ction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {" ascii
    $s6  = "ext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !s" ascii
    $s7  = "mpLifghtqhf = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s8  = "&& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s9  = "        bEvFBSp = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], e" ascii
    $s10 = "albumen((\"jordan\",\"whiting\",\"h\")+(\"belgrade\",\"thong\",\"tt\")+(\"soulless\",\"inadvertently\",\"focused\",\"dresser\"," ascii
    $s11 = "var ojJeCvs = [(\"slogan\",\"likes\",\"beneficial\",\"LTG\")+\"CC\"+\"bV\"+(\"primary\",\"whales\",\"trite\",\"writings\",\"NH\"" ascii
    $s12 = "Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, cont" ascii
    $s13 = "FCAHxMBL = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s14 = "        var HnwXd = new qSyXffPr(((\"professionals\",\"renunciation\",\"content\",\"\")+\"A\"+\"pO\"+\"DB.\" + \"\"+(\"album\"," ascii
    $s15 = "FCAHxMBL = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext " ascii
    $s16 = "generic = ((\"consultancy\", \"quadrant\", \"uhIbPasqr\", \"famed\", \"pwAEAAjDJkL\") + \"aRPOdUD\").riley();" fullword ascii
    $s17 = "ementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s18 = "l verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s19 = "mpLifghtqhf = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s20 = "String.prototype.riley = function () { return this.substr(0, 1); };" fullword ascii

  condition:
    uint16(0) == 0x6a62 and
    8 of them
}