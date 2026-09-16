rule sig_20160321_305c0f8af6759aa9f11697f3a60a1155 {
  meta:
    description = "datamaliciousorder - file 20160321_305c0f8af6759aa9f11697f3a60a1155.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "363a92db95ec90f22f34cc7532ce4f15b35ea8c41a3fb031caff4a57a3ea4227"

  strings:
    $s1  = ".length > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.re" ascii
    $s2  = "   wezJoORKMeU = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( token" ascii
    $s3  = "    KcXHxfFHmUV = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s4  = "|Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @par" ascii
    $s5  = "context, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match " ascii
    $s6  = "eed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s7  = "QDGWpCy = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s8  = "QDGWpCy = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s9  = "bramble = ((\"filling\", \"themes\", \"FuyjJsedeC\", \"mediate\", \"pMVhTEf\") + \"SAMjMzGWlRm\").heavy();" fullword ascii
    $s10 = "iambic((\"propitiatory\",\"booth\",\"h\")+\"tt\"+(\"chancellor\",\"dissipate\",\"p://cide\")+\"ac.mx/\"+\"wp\"+(\"tenable\",\"be" ascii
    $s11 = "ejFfmqf = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s12 = "        JPQNxCXyqyH = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s13 = "am {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, " ascii
    $s14 = "verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s15 = "ejFfmqf = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatche" ascii
    $s16 = "re\",\"magpie\",\"innovation\",\"as\")+\"onab\"+\"le\"+\"XMreas\"+\"on\"+(\"tunes\",\"debater\",\"framing\",\"ab\")+\"le\"+\"LH" ascii
    $s17 = "String.prototype.heavy = function () { return this.substr(0, 1); };" fullword ascii
    $s18 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s19 = "        JPQNxCXyqyH = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s20 = "        jsdbfjor[sdIqt[ignominiousI + 1]](quarters, 1, \"hhmYKhUfW\" === \"hLaborPgd\"); OcGOqm = \" Precompiled matchers will s" ascii

  condition:
    uint16(0) == 0x5361 and
    8 of them
}