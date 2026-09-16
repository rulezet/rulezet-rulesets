rule sig_20160321_0d2b4fe891455691727f63a327598cfb {
  meta:
    description = "datamaliciousorder - file 20160321_0d2b4fe891455691727f63a327598cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d68bc50b5bf87632253af61010f5c551ec5a17c6e1127262f113b792c8987510"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "   LVMKoyDzggc = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s3  = "    KFbJQq = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {String|F" ascii
    $s4  = "obsession(\"h\"+\"tt\"+(\"dominate\",\"scowl\",\"phosphorescence\",\"ripen\",\"p:\")+\"//ti\"+\"kl\"+\"as\"+(\"technical\",\"glo" ascii
    $s5  = "tion} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @param {A" ascii
    $s6  = "xt, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match = !se" ascii
    $s7  = "KfkFIXUjmvw = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s8  = "KfkFIXUjmvw = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s9  = "WoVLndbi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s10 = "& tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s11 = "        zPOMirYY = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s12 = "obsession(\"h\"+\"tt\"+(\"dominate\",\"scowl\",\"phosphorescence\",\"ripen\",\"p:\")+\"//ti\"+\"kl\"+\"as\"+(\"technical\",\"glo" ascii
    $s13 = "intermittently = ((\"homesick\", \"regency\", \"FoQEpVSCWx\", \"triple\", \"piueetaf\") + \"hYvLOv\").awkwardly();" fullword ascii
    $s14 = "rray} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, conte" ascii
    $s15 = "String.prototype.awkwardly = function () { return this.substr(0, 1); };" fullword ascii
    $s16 = "WoVLndbi = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatch" ascii
    $s17 = "function obsession(synopsis, feels) {" fullword ascii
    $s18 = "rify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s19 = "        Hxwrvlb[njCEKyEOn[boobyI + 1]](abashed, 1, \"ENmntUnOn\" === \"EFCKAKzn\"); RLOxHwJrL = \" Precompiled matchers will sti" ascii
    $s20 = "        Hxwrvlb[njCEKyEOn[boobyI + 1]](abashed, 1, \"ENmntUnOn\" === \"EFCKAKzn\"); RLOxHwJrL = \" Precompiled matchers will sti" ascii

  condition:
    uint16(0) == 0x7457 and
    8 of them
}