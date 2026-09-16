rule sig_20160301_77f6759fbf13f22d1e733db96d88c45c {
  meta:
    description = "datamaliciousorder - file 20160301_77f6759fbf13f22d1e733db96d88c45c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d8168cede474f462821546464afa95b76ca452aa4345e89b95c38b2f06cfd5"

  strings:
    $s1 = "l\" + \"a\\u0072\", \"fact\", \"w\\u0072it\\u0065\")](parallelAutomobile[(\"\\u0076\" + \"a\" + \"\\u0063\\u0075\\u0075\\u006d\"" ascii
    $s2 = "while (parallelAutomobile[(\"\\u0072ea\" + \"d\\u0079\" + \"s\\u0074\" + \"\\u0061\\u0074\" + \"e\")] < ((([+!+[]])) * (4 | 0)))" ascii
    $s3 = "transplantDeclaration = ((([+!+[]])), this);" fullword ascii
    $s4 = "} catch (collectorCitation) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}