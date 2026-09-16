rule sig_20170123_86568a682abc06bc6da3d7e6075ade66 {
  meta:
    description = "datamaliciousorder - file 20170123_86568a682abc06bc6da3d7e6075ade66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7553bcb02004cf491cdca36a992802a6e31cab71d7f62aff9ab3c4e4e47f391b"

  strings:
    $s1 = "//if ([\"aqzyv\", \"unabern\", \"moqo\", \"hyxw\", \"unlupat\", new Function([\"fymifz\", \"rdon\", \"pcakmosk\", \"opamfy\", \"" ascii
    $s2 = "tajqames0 = this[[\"rnig\", \"vez\", \"jehyh\", \"nlicge\", \"vsopun\", \"saba\", \"ovagsyc\", \"uvika\", \"vxekjaqu\", \"yrqure" ascii
    $s3 = "tajqames0 = this[[\"rnig\", \"vez\", \"jehyh\", \"nlicge\", \"vsopun\", \"saba\", \"ovagsyc\", \"uvika\", \"vxekjaqu\", \"yrqure" ascii
    $s4 = "//if ([\"aqzyv\", \"unabern\", \"moqo\", \"hyxw\", \"unlupat\", new Function([\"fymifz\", \"rdon\", \"pcakmosk\", \"opamfy\", \"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}