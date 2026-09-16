rule sig_20160824_97005bac6399691b1da65e97ecf6dca7 {
  meta:
    description = "datamaliciousorder - file 20160824_97005bac6399691b1da65e97ecf6dca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c78ba0851ae6bc89109c516fe2995a7f0774b350854b497d282a67cb3a742fe"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}