rule sig_20160321_82a79b63977ec2bddf999b55e43bdbf9 {
  meta:
    description = "datamaliciousorder - file 20160321_82a79b63977ec2bddf999b55e43bdbf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b8480821ad5a2da861d56a1048200ec74e56edd7be5271314ba68f23985e9"

  strings:
    $s1  = "ength > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.rela" ascii
    $s2  = "   mTWTSYKPF = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens." ascii
    $s3  = "    MWuwFnUFgv = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Stri" ascii
    $s4  = "Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @para" ascii
    $s5  = "ed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s6  = "ontext, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match =" ascii
    $s7  = "zEqoAwgqzRk = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s8  = "unattended(\"h\"+\"ttp://seba\"+\"stians\"+\"anni.org\"+\"/w\"+\"p-co\"+(\"sending\",\"cartoon\",\"gangrene\",\"nt\")+\"en\"+\"t" ascii
    $s9  = "zEqoAwgqzRk = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostConte" ascii
    $s10 = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s11 = "SkDzYA = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s12 = "        KboAnbqG[mAcblhbD[blameI + 1]](postmaster, 1, \"VkRIDbya\" === \"XrNHnOCyPJ\"); nkSree = \" Precompiled matchers will st" ascii
    $s13 = "        KboAnbqG[mAcblhbD[blameI + 1]](postmaster, 1, \"VkRIDbya\" === \"XrNHnOCyPJ\"); nkSree = \" Precompiled matchers will st" ascii
    $s14 = "        shdcztdT = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [], " ascii
    $s15 = "m {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, c" ascii
    $s16 = "        var postmaster = SUvTp + \"/\" + leonine + mAcblhbD[blameI];" fullword ascii
    $s17 = "unattended(\"h\"+\"ttp://seba\"+\"stians\"+\"anni.org\"+\"/w\"+\"p-co\"+(\"sending\",\"cartoon\",\"gangrene\",\"nt\")+\"en\"+\"t" ascii
    $s18 = "copper = ((\"storey\", \"staying\", \"tehlvXBpUEE\", \"serbia\", \"pOcFUNAOB\") + \"DQeefDh\").outgrown();" fullword ascii
    $s19 = "erify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s20 = "ch ) { match = tokenize( selector ); } i = match.length; while ( i-- ) { cached = matcherFromTokens( match[i] ); if ( cached[ ex" ascii

  condition:
    uint16(0) == 0x6d58 and
    8 of them
}