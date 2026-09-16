rule sig_20161006_74d1d7f5059fd35936e38441bf58190d {
  meta:
    description = "datamaliciousorder - file 20161006_74d1d7f5059fd35936e38441bf58190d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d364edf86bf8ec2789eec445d83ac5e69f630e47f9d0daaaa7e26edfc95518af"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}