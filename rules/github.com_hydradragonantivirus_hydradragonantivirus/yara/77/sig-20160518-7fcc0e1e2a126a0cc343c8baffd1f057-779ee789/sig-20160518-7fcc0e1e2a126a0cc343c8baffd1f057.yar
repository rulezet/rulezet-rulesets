rule sig_20160518_7fcc0e1e2a126a0cc343c8baffd1f057 {
  meta:
    description = "datamaliciousorder - file 20160518_7fcc0e1e2a126a0cc343c8baffd1f057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f4a7e3f25c1ab8f5bdf8e3fb7ccd8264bc2adf0fc56764226801b61079ba0db"

  strings:
    $s1  = "var expiate = [truck, henderson,evergreen,  \"\"+\".\"+(\"firefox\",\"padlock\",\"galaxy\",\"follows\",\"beads\",\"contacting\"," ascii
    $s2  = "evasively = ((\"antithesis\", \"chairman\", \"header\", \"subsist\", \"svdLdzCoYHX\") + \"cUEUeajrkI\").sexuality2();" fullword ascii
    $s3  = "exhibit = ((\"manse\", \"orlando\", \"nucleus\", \"tropic\", \"pHryNjVhDLyR\") + \"bhCLgXfoE\").sexuality2();" fullword ascii
    $s4  = "        sensuous[(exhibit + \"o\"+(\"postmaster\",\"theaters\",\"vancouver\",\"antigua\",\"prelude\",\"shuttle\",\"crease\",\"ba" ascii
    $s5  = "weasel = ((\"kelkoo\", \"bankruptcy\", \"abetted\", \"courtesy\", \"ELXmXPbXVWuf\") + \"XrPFXmxXzVN\").sexuality2();" fullword ascii
    $s6  = "craggy(\"aHR0cDovLw==\".sexuality4()+\"\\u0074\\u0068\\u0065\\u006D\\u0061\\u0074\\u0068\\u0077\\u0065\\u0062\\u0073\\u0069\\u00" ascii
    $s7  = "remainder = remainder+ expiate.shift();" fullword ascii
    $s8  = "String.prototype.sexuality = function () {" fullword ascii
    $s9  = "String.prototype.sexuality4 = function() {" fullword ascii
    $s10 = "String.prototype.sexuality2 = function () {" fullword ascii
    $s11 = "        sensuous[(\"standing\",\"maneuver\",\"builds\",\"greatgrandfather\",\"aquiline\",\"twill\",\"encompass\",\"s\")+\"aveT\"" ascii
    $s12 = "        sensuous[(\"standing\",\"maneuver\",\"builds\",\"greatgrandfather\",\"aquiline\",\"twill\",\"encompass\",\"s\")+\"aveT\"" ascii
    $s13 = "var evergreen =\"JVconjureRFTVconjureAl\".sexuality4();" fullword ascii
    $s14 = "var truck = \"QWconjureN0aXZconjurelWE9iaconjuremVjdA=conjure=\".sexuality4();" fullword ascii
    $s15 = "connectors = this;" fullword ascii
    $s16 = "var sobriety = this[expiate.shift()];" fullword ascii
    $s17 = "var sarah = new sobriety(claudia[1]);" fullword ascii
    $s18 = "        sensuous[(exhibit + \"o\"+(\"postmaster\",\"theaters\",\"vancouver\",\"antigua\",\"prelude\",\"shuttle\",\"crease\",\"ba" ascii
    $s19 = "var diploma = {" fullword ascii
    $s20 = "ements, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}