rule sig_20160525_db3e619e8f7f9d6d96bb1b9c640a4bfe {
  meta:
    description = "datamaliciousorder - file 20160525_db3e619e8f7f9d6d96bb1b9c640a4bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef99159ac0115a5879359c2c05de4bbf161d5c68c09ed35e92816a497b551009"

  strings:
    $s1 = ";};imb nruter{)imb(rerednerb noitcnuf\\n;\"733x\\\\4\" = imc rav\\n;\"tt86x\\\\\" = eixodd rav\\n;\":07x\\\\\" = gsmd rav\\n;\"f" ascii
    $s2 = "x\\\\\" = tsilslianbmuhton rav;};imn nruter{)imn(rerednern noitcnuf\\n;\"47x\\\\gnel\" = gsmo rav\\n;)3(]\"tAra\"+\"86x\\\\\"+\"" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}