rule sig_20160516_3ccc65ad092a5d8522ea42475ab24c46 {
  meta:
    description = "datamaliciousorder - file 20160516_3ccc65ad092a5d8522ea42475ab24c46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb8ead85dccb165b71588423eb914025074eeb8c777895aecf68785ebdf9fb93"

  strings:
    $s1  = "weasel = ((\"seducer\", \"plane\", \"beget\", \"niggers\", \"EPDbQdkKq\") + \"TiTJoOYbGo\").early2();" fullword ascii
    $s2  = "        grande[(abstracted + \"o\"+(\"idiocy\",\"unitarian\",\"divest\",\"tradesman\",\"exemplary\",\"peterson\",\"flood\",\"cre" ascii
    $s3  = "se())](sighting, execution);" fullword ascii
    $s4  = "var execution = 6/6;" fullword ascii
    $s5  = "sheaf[atkins.shift()](fiddling, execution, true);dsmVqzVyEyh = \"_F17_\";" fullword ascii
    $s6  = "comes(\"aHR0cDovLw==\".early4()+\"\\u0062\\u006C\\u006F\\u0032\\u0030\\u0030\\u0030\\u002E\\u0067\\u006C\\u0075\\u0070\\u006F\\u" ascii
    $s7  = "    combines.darken = combines.perspicuity[((\"purplish\",\"dispersion\",\"brier\",\"prerogative\",\"seduce\",\"alderman\",\"lau" ascii
    $s8  = "var breakwater=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".early4())&&visitation[\"c3RhdHVz\".early4()] +\"\"==\"MjAw\".earl" ascii
    $s9  = "var breakwater=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".early4())&&visitation[\"c3RhdHVz\".early4()] +\"\"==\"MjAw\".earl" ascii
    $s10 = "obity\",\"trestle\",\"lapland\",\"randy\",\"sharpness\",\"ip\")+\"t:\"+(\"symbols\",\"humid\",\"revision\",\"brochures\",\"relie" ascii
    $s11 = "var atkins = [cosmic, fatty,stoicism,  \"\"+\".\"+(\"lesbians\",\"container\",\"embellish\",\"importance\",\"lingo\",\"nostril\"" ascii
    $s12 = "        grande[(abstracted + \"o\"+(\"idiocy\",\"unitarian\",\"divest\",\"tradesman\",\"exemplary\",\"peterson\",\"flood\",\"cre" ascii
    $s13 = "abstracted = ((\"unmindful\", \"modena\", \"appeals\", \"wallet\", \"pvDvfzyOpx\") + \"qJtsFpclhD\").early2();" fullword ascii
    $s14 = "fiddling = fiddling+ atkins.shift();" fullword ascii
    $s15 = "String.prototype.early = function () {" fullword ascii
    $s16 = "    return combines.darken;" fullword ascii
    $s17 = "function comes(paragraphs, resistant) {" fullword ascii
    $s18 = "var atkins = [cosmic, fatty,stoicism,  \"\"+\".\"+(\"lesbians\",\"container\",\"embellish\",\"importance\",\"lingo\",\"nostril\"" ascii
    $s19 = "String.prototype.early4 = function() {" fullword ascii
    $s20 = "String.prototype.early2 = function () {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}