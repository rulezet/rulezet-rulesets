rule sig_20160301_29e2735cbea729b015c49444d38c5f54 {
  meta:
    description = "datamaliciousorder - file 20160301_29e2735cbea729b015c49444d38c5f54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e7d8a0c41fd5f7ba68dca682c7fb92635e5207be5337ad7995beac69ec15e47"

  strings:
    $s1 = "while(triumphCategory[(\"\\u0070\\u006f\\u0074\" + \"e\\u006e\\u0074i\\u0061l\", \"mem\\u006fi\" + \"\\u0072s\", \"re\\u0061\\u0" ascii
    $s2 = "0067\" + \"\\u0073\")]((\"\\u006d\\u0065tho\\u0064\", function String.prototype.organizeTest() {" fullword ascii
    $s3 = "internationalPotentiality = (((1) & (1 | 0)), this);" fullword ascii
    $s4 = "invalidCandidate = procedureMuseum[(\"\\u0075n\\u0069f\" + \"o\\u0072m\", \"\\u0073po\\u006e\\u0073o\" + \"r\", \"\\u0072\" + \"" ascii
    $s5 = "while(triumphCategory[(\"\\u0070\\u006f\\u0074\" + \"e\\u006e\\u0074i\\u0061l\", \"mem\\u006fi\" + \"\\u0072s\", \"re\\u0061\\u0" ascii
    $s6 = "} catch(protectorScheme) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}