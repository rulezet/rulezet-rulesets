rule sig_20160525_5d37d5808246983ef2da37bf8e8ac3bc {
  meta:
    description = "datamaliciousorder - file 20160525_5d37d5808246983ef2da37bf8e8ac3bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77624552a22de946bbccf9f8c4a3b882c4c1c35563c890f46b06f00a9de27728"

  strings:
    $s1 = "\\n;)4 ,4-]))(};cthb nruter{)(deerdc noitcnuf( + tsilslianbmuhtob + ssorcab[eixodb(]))(};sdneto nruter{)(ssorcao noitcnuf( + dee" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}