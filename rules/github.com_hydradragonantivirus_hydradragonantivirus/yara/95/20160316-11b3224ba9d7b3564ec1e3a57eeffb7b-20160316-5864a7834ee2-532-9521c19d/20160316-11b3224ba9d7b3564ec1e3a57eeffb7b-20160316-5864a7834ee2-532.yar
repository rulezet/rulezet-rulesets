rule _20160316_11b3224ba9d7b3564ec1e3a57eeffb7b_20160316_5864a7834ee2_532 {
  meta:
    description = "datamaliciousorder - from files 20160316_11b3224ba9d7b3564ec1e3a57eeffb7b.js, 20160316_5864a7834ee2f57f024ff40666fca50f.js, 20160316_60d8799ca8730da6fe15be5aed4343a0.js, 20160316_c39aef5bc8edade313196b764463b5e7.js, 20160316_d41ce0d655ace64b4075762bb5872fdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "228262ab637a185184a32fa72a406afe89171f13c8cb416f78f62d91659bb280"
    hash2       = "9665bfa19242dc6929af98aec17f9df512f757bd274413e90dbfc5cd31b6070d"
    hash3       = "a6e486236e71f8e6114e7c4d6ddada3a39451a12b700991a47d54f79d6259735"
    hash4       = "8e36b3784381ab50c927d1e89b4b0b9152b7b9a6ae67af98975a06d27e138069"
    hash5       = "fc28b22d0a6ee85ab1f34226d4bd25ca1441b676e62a4b1cfd50031541b24caa"

  strings:
    $s1  = "rnamespace[rscriptTypeMasked + \"pt\"][createPseudo + \"p\"](((Math.pow(handle, 2) - parseJSON) / (11 | multipleContexts)));" fullword ascii
    $s2  = "rheaders = 4744, swing = \"onseB\", fadeIn = 81, rfocusMorph = 3, ofType = \"e\", parseHTML = \"%TEMP%\";" fullword ascii
    $s3  = "stopImmediatePropagation(using, refElements, (2 / (next - 6)), forward + \"File\");" fullword ascii
    $s4  = "responseContainer = new rnamespace[global + \"eXObj\" + keyHooks](\"MSXML\" + postSelector + \"TTP\");" fullword ascii
    $s5  = "rscriptTypeMasked = \"WScri\", forward = \"saveTo\", rparentsprev = \"Strea\", useCache = \"o\", bp = \"ron\", camelCase = \"pt." ascii
    $s6  = "responseContainer[useCache + \"p\" + ofType + \"n\"](tweeners + \"ET\", funescape + \"//i\" + triggerHandler + \"OLYC\" + identi" ascii
    $s7  = "using = pop[active + \"Envi\" + bp + \"mentS\" + MAX_NEGATIVE + \"s\"](parseHTML + \"/\") + cssShow + \"i\" + lang + \".\" + par" ascii
    $s8  = "refElements = new rnamespace[Sizzle + \"iveX\" + handler](\"ADODB.\" + rparentsprev + \"m\");" fullword ascii
    $s9  = "responseContainer[\"se\" + all](null);" fullword ascii
    $s10 = "using = pop[active + \"Envi\" + bp + \"mentS\" + MAX_NEGATIVE + \"s\"](parseHTML + \"/\") + cssShow + \"i\" + lang + \".\" + par" ascii
    $s11 = "responseContainer[useCache + \"p\" + ofType + \"n\"](tweeners + \"ET\", funescape + \"//i\" + triggerHandler + \"OLYC\" + identi" ascii
    $s12 = "rejectWith = 30, identifier = \"ROSSC\", source = \"close\", pageXOffset = \"w\";" fullword ascii
    $s13 = "fx = \"iti\", MAX_NEGATIVE = \"tring\", m = \"php\", keyHooks = \"ect\", trim = 580;" fullword ascii
    $s14 = "handle = 92714," fullword ascii
    $s15 = "return elementMatchers[pseudo](attaches, clientTop);" fullword ascii
    $s16 = "var global = \"Activ\"," fullword ascii
    $s17 = "handler = \"Object\"," fullword ascii
    $s18 = "active = \"Expand\";" fullword ascii
    $s19 = "Sizzle = \"Act\";" fullword ascii
    $s20 = "next = 7," fullword ascii

  condition:
    (uint16(0) == 0x6f70 and (8 of them)
    ) or (all of them)
}