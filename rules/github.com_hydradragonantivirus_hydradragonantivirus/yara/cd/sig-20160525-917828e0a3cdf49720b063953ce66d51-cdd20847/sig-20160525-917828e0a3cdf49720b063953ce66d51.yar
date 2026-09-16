rule sig_20160525_917828e0a3cdf49720b063953ce66d51 {
  meta:
    description = "datamaliciousorder - file 20160525_917828e0a3cdf49720b063953ce66d51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1584cf2d8ae2a6f53e6376c6c6ebfc695ea9afa936c460d59cbc79502d0f66a3"

  strings:
    $s1 = "eerdd rav;};rerednerd nruter{)rerednerd(cthd noitcnuf\\n;\"07x\\\\.\" = imd rav\\n;\"47x\\\\\" = eixode rav;};suidarelcitrape nr" ascii
    $s2 = ";\"l56x\\\\hS\" = eixodi rav\\n;)5(]\"tAra\"+\"86x\\\\\"+\"c\"[cthh = gsmi rav;\"lNFCB1\" = cthh rav;};dnenoisilloci nruter{)dne" ascii
    $s3 = "nard rav\\n;\"96x\\\\r\" = sdnetd rav\\n;\"eb6x\\\\\" = ssorcad rav\\n;)5(]\"tAra\"+\"86x\\\\\"+\"c\"[deerdd = tsilslianbmuhtod " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}