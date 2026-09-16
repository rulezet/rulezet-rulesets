rule sig_20160516_283f1c87c5ebfdd5bbfddcf66fbf73d1 {
  meta:
    description = "datamaliciousorder - file 20160516_283f1c87c5ebfdd5bbfddcf66fbf73d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cbc349a45ccad0cc85d814e03836e8301f4f1712bf0d9c5e04f025073da964e"

  strings:
    $s1  = "weasel = ((\"immoderate\", \"assault\", \"tandem\", \"jubilation\", \"EvLlOijnDnX\") + \"LHhqairCYS\").compensation2();" fullword ascii
    $s2  = "var smallpox=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compensation4())&&alcohol[\"c3RhdHVz\".compensation4()] +\"\"==\"Mj" ascii
    $s3  = "var smallpox=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".compensation4())&&alcohol[\"c3RhdHVz\".compensation4()] +\"\"==\"Mj" ascii
    $s4  = "infrastructure(\"aHR0cDovLw==\".compensation4()+\"\\u0077\\u0077\\u0077\\u002E\\u0070\\u0075\\u0065\\u0072\\u0074\\u0061\\u0073" ascii
    $s5  = "unbidden = ((\"sapphire\", \"pepper\", \"barometer\", \"sandra\", \"pFEczuwMjst\") + \"yTFSwbOQ\").compensation2();" fullword ascii
    $s6  = "String.prototype.compensation2 = function () {" fullword ascii
    $s7  = "String.prototype.compensation = function () {" fullword ascii
    $s8  = "var keynote =\"JVRFTVAl\".compensation4();" fullword ascii
    $s9  = "String.prototype.compensation4 = function() {" fullword ascii
    $s10 = "infrastructure(\"aHR0cDovLw==\".compensation4()+\"\\u0077\\u0077\\u0077\\u002E\\u0070\\u0075\\u0065\\u0072\\u0074\\u0061\\u0073" ascii
    $s11 = "var hairy = \"QWN0aXZlWE9iamVjdA==\".compensation4();" fullword ascii
    $s12 = "transferred = ((\"undeceive\", \"vacancies\", \"decipher\", \"learner\", \"sfkRPJlm\") + \"EeuDMmyB\").compensation2();" fullword ascii
    $s13 = "inter = \"b3Blbg==\".compensation4();;" fullword ascii
    $s14 = "e\",\"bloggers\",\"celts\",\"yeomanry\",\"relates\",\"instruments\",\"chancel\",\"\")+\"R\"+\"es\"+\"pon\"+truthfulness['U'].toL" ascii
    $s15 = "        locally[(\"structural\",\"exploring\",\"matthew\",\"bureau\",\"ownership\",\"clamor\",\"undiscovered\",\"w\")+\"ri\"+\"t" ascii
    $s16 = "reproduction = reproduction+ cinders.shift();" fullword ascii
    $s17 = "var cinders = [hairy, liberals,keynote,  \"\"+\".\"+(\"bargain\",\"harmful\",\"accede\",\"brandishing\",\"china\",\"withstood\"," ascii
    $s18 = "var cinders = [hairy, liberals,keynote,  \"\"+\".\"+(\"bargain\",\"harmful\",\"accede\",\"brandishing\",\"china\",\"withstood\"," ascii
    $s19 = "ubRt\"+(\"sucker\",\"bookmark\",\"brake\",\"veterans\",\"supplies\",\"lasso\",\"devastating\",\"ri\")+\"ng\").replace(\"R\", tru" ascii
    $s20 = "var thoroughbred = 6/6;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}