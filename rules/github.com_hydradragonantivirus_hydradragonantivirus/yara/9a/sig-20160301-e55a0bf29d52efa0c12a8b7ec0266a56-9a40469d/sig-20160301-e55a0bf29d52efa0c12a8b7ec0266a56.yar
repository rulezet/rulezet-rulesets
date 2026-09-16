rule sig_20160301_e55a0bf29d52efa0c12a8b7ec0266a56 {
  meta:
    description = "datamaliciousorder - file 20160301_e55a0bf29d52efa0c12a8b7ec0266a56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341393d4abd917dc96665f29e90e7f699feb71ed5d177a1bd0d78c1bf308c14a"

  strings:
    $s1 = "while(lectureUniversity[(\"\\u006d\\u0065\\u0064\\u0069\" + \"ta\\u0074\" + \"\\u0065\", \"p\\u006f\\u0074\\u0065n\" + \"\\u0074" ascii
    $s2 = "while(lectureUniversity[(\"\\u006d\\u0065\\u0064\\u0069\" + \"ta\\u0074\" + \"\\u0065\", \"p\\u006f\\u0074\\u0065n\" + \"\\u0074" ascii
    $s3 = "uniformGuest = (((0 ^ 0) + (1 | 1)), this);" fullword ascii
    $s4 = "dogmaAutopilot[(\"s\\u0074\\u0061\\u0074u\" + \"\\u0073\", function String.prototype.pulseForum() {" fullword ascii
    $s5 = "} catch(collectionForum) {};" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    all of them
}