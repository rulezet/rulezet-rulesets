rule sig_20160525_994c77754b2ac6fbba0a241482d99f30 {
  meta:
    description = "datamaliciousorder - file 20160525_994c77754b2ac6fbba0a241482d99f30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cd46dd1716969d9baf0528e70c3c6d1bb1f666a5305c8dda29c6e9096f3a670"

  strings:
    $s1 = ";};imb nruter{)imb(rerednerb noitcnuf\\n;\"733x\\\\4\" = imc rav\\n;\"tt86x\\\\\" = eixodd rav\\n;\":07x\\\\\" = gsmd rav\\n;\"f" ascii
    $s2 = "x\\\\\" = tsilslianbmuhton rav;};imn nruter{)imn(rerednern noitcnuf\\n;\"47x\\\\gnel\" = gsmo rav\\n;)3(]\"tAra\"+\"86x\\\\\"+\"" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}