rule sig_20160321_0d14ecad1600d1e10d66dcb2154b681b {
  meta:
    description = "datamaliciousorder - file 20160321_0d14ecad1600d1e10d66dcb2154b681b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab2ed03a00327ccb72eba820bc809e517e4c4d06d5060ce48e073f84772dcb4f"

  strings:
    $s1  = "pathology(\"h\"+\"tt\"+(\"headgear\",\"muffin\",\"preceptor\",\"holders\",\"p:\")+(\"ascension\",\"tears\",\"tepee\",\"obviate\"" ascii
    $s2  = "pathology(\"h\"+\"tt\"+(\"headgear\",\"muffin\",\"preceptor\",\"holders\",\"p:\")+(\"ascension\",\"tears\",\"tepee\",\"obviate\"" ascii
    $s3  = "length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rel" ascii
    $s4  = "    qLAjPQrUV = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Strin" ascii
    $s5  = "   dvcvYIRbSY = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens" ascii
    $s6  = "unction} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param" ascii
    $s7  = "weighted = ((\"visit\", \"piper\", \"BGdlhFq\", \"folders\", \"phTjuzYo\") + \"pXODDx\").pronunciation();" fullword ascii
    $s8  = "ntext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = " ascii
    $s9  = "d && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s10 = "lzmeGRolE = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s11 = "lzmeGRolE = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext" ascii
    $s12 = "DflzEVYCjOQ = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii
    $s13 = "        jCzXVWhzxG = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = []" ascii
    $s14 = "function pathology(unmerciful, assiduous) {" fullword ascii
    $s15 = "billiards = ((\"refresh\", \"insinuation\", \"iUkhsnCOX\", \"wichita\", \"sUcpCgjXTavU\") + \"cVeQRlSePL\").pronunciation();" fullword ascii
    $s16 = " {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, co" ascii
    $s17 = "        srkrzn[\"w\"+\"ri\"+(\"territory\",\"azores\",\"te\")](YaGln[\"\"+(\"river\",\"suburban\",\"autocrat\",\"dissimilarity\"" ascii
    $s18 = " elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s19 = "String.prototype.pronunciation = function () { return this.substr(0, 1); };" fullword ascii
    $s20 = "DflzEVYCjOQ = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMa" ascii

  condition:
    uint16(0) == 0x6671 and
    8 of them
}