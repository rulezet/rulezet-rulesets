rule sig_20160321_d57ba1502b4ef0e3e59002902ed24f9d {
  meta:
    description = "datamaliciousorder - file 20160321_d57ba1502b4ef0e3e59002902ed24f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d46fb75eba790bb3ff42b39dbb1e9aa1fdf58d0a7a9b40913153731f36098da0"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "    FDacgaxz = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String" ascii
    $s3  = "   PTOnkcuNnKi = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s4  = "nction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param " ascii
    $s5  = "text, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !" ascii
    $s6  = " && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "wouGyg = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s8  = "wouGyg = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext = " ascii
    $s9  = "WYcbUIjnYgW = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s10 = "        IgqKHOFdy = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii
    $s11 = "\"ri\"+\"ngs\", (\"downloadable\",\"conflagration\",\"coordinate\",\"\")+\"%\"+\"TE\"+\"MP%\", \"\"+\".\"+(\"societies\",\"diges" ascii
    $s12 = "{Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, con" ascii
    $s13 = "output = ((\"venomous\", \"gleefully\", \"oHXDbdGS\", \"shower\", \"pGlXdMpMOsFh\") + \"WfaqDDsvXJ\").specially();" fullword ascii
    $s14 = "ify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s16 = "WYcbUIjnYgW = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s17 = "String.prototype.specially = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = "        cVzwF[(output + \"o\"+(\"deprivation\",\"whoop\",\"opportunities\",\"interval\",\"Di\")+(\"fella\",\"point\",\"restauran" ascii
    $s19 = "        MwDtl[AIDkTsEq[toilsomeI + 1]](beaches, 1, \"YASGLdnY\" === \"tYQgVPXkiM\"); JxwSHfl = \" Precompiled matchers will stil" ascii
    $s20 = "        IgqKHOFdy = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []," ascii

  condition:
    uint16(0) == 0x6a4f and
    8 of them
}