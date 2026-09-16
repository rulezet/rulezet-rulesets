rule sig_20160301_51c667a26588fc2f396c837a048a72ce {
  meta:
    description = "datamaliciousorder - file 20160301_51c667a26588fc2f396c837a048a72ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ece503ba82728fd08c53b861f77985f38d7b7cf90645803ba0f20946c09272d"

  strings:
    $s1 = "while(militaryCompilation[(\"\\u0069\" + \"\\u006d\\u0069ta\\u0074\\u0065\", \"o\\u0063\" + \"c\\u0061\" + \"\\u0073\" + \"i\" +" ascii
    $s2 = "while(militaryCompilation[(\"\\u0069\" + \"\\u006d\\u0069ta\\u0074\\u0065\", \"o\\u0063\" + \"c\\u0061\" + \"\\u0073\" + \"i\" +" ascii
    $s3 = "yardIdea[(\"orga\" + \"ni\" + \"z\\u0061t\" + \"\\u0069\\u006fn\", \"synthe\" + \"\\u0073\\u0069\\u0073\", function String.proto" ascii
    $s4 = "yardIdea[(\"orga\" + \"ni\" + \"z\\u0061t\" + \"\\u0069\\u006fn\", \"synthe\" + \"\\u0073\\u0069\\u0073\", function String.proto" ascii
    $s5 = "sion() {" fullword ascii
    $s6 = "organCentre = ((([+!+[]])), this);" fullword ascii
    $s7 = "} catch(skeletonTheory) {};" fullword ascii

  condition:
    uint16(0) == 0x726f and
    all of them
}