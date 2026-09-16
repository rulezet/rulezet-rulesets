rule sig_20160517_7eab37909bebc118a34c9cf728247aed {
  meta:
    description = "datamaliciousorder - file 20160517_7eab37909bebc118a34c9cf728247aed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cecef709a497a7e24f983190cb0ec2c0076d84b5786e76cac8cf886630aa279"

  strings:
    $s1  = "var syntax = [angel, designated,allen,  \"\"+\".\"+(\"extravagantly\",\"languish\",\"moses\",\"director\",\"elected\",\"village" ascii
    $s2  = "epilepsy = epilepsy+ syntax.shift();" fullword ascii
    $s3  = "weasel = ((\"colossus\", \"sheer\", \"favourably\", \"curtail\", \"EGkplhDHPmG\") + \"xHzEaWOejyN\").adept2();" fullword ascii
    $s4  = "var syntax = [angel, designated,allen,  \"\"+\".\"+(\"extravagantly\",\"languish\",\"moses\",\"director\",\"elected\",\"village" ascii
    $s5  = "var eclipse = syntax.pop().split(\"" fullword ascii
    $s6  = "String.prototype.adept4 = function() {" fullword ascii
    $s7  = "String.prototype.adept2 = function () {" fullword ascii
    $s8  = "String.prototype.adept = function () {" fullword ascii
    $s9  = "for (var i in cocoon){unalterable = unalterable.replace(i, cocoon[i]);}" fullword ascii
    $s10 = "var traffic = this[syntax.shift()];" fullword ascii
    $s11 = "var cocoon = {" fullword ascii
    $s12 = ")](bearable, entrepreneur);" fullword ascii
    $s13 = "var bearable = 0;" fullword ascii
    $s14 = "var planning = new traffic(eclipse[0]);" fullword ascii
    $s15 = "var entrepreneur = 6/6;" fullword ascii
    $s16 = "bivouac = \"_F2_\";" fullword ascii
    $s17 = "        dionysus[(\"pyjamas\",\"thailand\",\"microsoft\",\"wicket\",\"denise\",\"terminology\",\"product\",\"s\")+\"aveT\"+\"oF" ascii
    $s18 = "var angel = \"QWN0instrumentalityaXZlWE9iinstrumentalityamVjdA==instrumentality\".adept4();" fullword ascii
    $s19 = "unalterable = this;" fullword ascii
    $s20 = "        dionysus[(\"pyjamas\",\"thailand\",\"microsoft\",\"wicket\",\"denise\",\"terminology\",\"product\",\"s\")+\"aveT\"+\"oF" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}