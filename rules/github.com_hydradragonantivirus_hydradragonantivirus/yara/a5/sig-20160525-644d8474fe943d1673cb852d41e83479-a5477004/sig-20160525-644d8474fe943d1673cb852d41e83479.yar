rule sig_20160525_644d8474fe943d1673cb852d41e83479 {
  meta:
    description = "datamaliciousorder - file 20160525_644d8474fe943d1673cb852d41e83479.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f4ad366915b11dc3d1cdd53011d518d042903cfb95aa84cde4603b7e88d92"

  strings:
    $s1 = "= cthm rav\\n;\"BDOD14x\\\\\" = imm rav\\n;\"47x\\\\S.\" = eixodn rav\\n;\"16x\\\\e27x\\\\\" = gsmn rav\\n;)5(]\"tAra\"+\"86x" ascii
    $s2 = "ssorcae nruter{)(tsilslianbmuhtoe noitcnuf(+deerde + modnare+keppele+gedotdare+me+dnenoisilloce+gsme + ))(};eixode nruter{)(suid" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}