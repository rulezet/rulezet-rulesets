rule sig_20160525_d2866bfd920c007549c89b787471bea5 {
  meta:
    description = "datamaliciousorder - file 20160525_d2866bfd920c007549c89b787471bea5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d48503133d8e6045000526cedfc88c9be49e0e2ea4dc70e2c6353f6bed39dee6"

  strings:
    $s1 = "lock noitcnuf([tpircSW{ )e( hctac" fullword ascii
    $s2 = "tsilslianbmuhtol noitcnuf\\n;\"r77x\\\\\" = rerednerl rav\\n;\"56x\\\\ti\" = iml rav;};gsmm nruter{)gsmm(eixodm noitcnuf\\n;\"e2" ascii
    $s3 = "fc nruter{)ecapsetihwxelfc(keppelc noitcnuf;};gedotdarc nruter{)gedotdarc(mc noitcnuf;};dnenoisillocc nruter{)dnenoisillocc(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}