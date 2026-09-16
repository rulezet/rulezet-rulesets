rule sig_20160525_6ecce1d9a2355407324780cfe24782f2 {
  meta:
    description = "datamaliciousorder - file 20160525_6ecce1d9a2355407324780cfe24782f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5323b7b1d23a5b6722292c02d70cf5b6442ff4329d66d663dca26f036e7d3c9d"

  strings:
    $s1 = "\\n;)4 ,4-]))(};cthb nruter{)(deerdc noitcnuf( + tsilslianbmuhtob + ssorcab[eixodb(]))(};sdneto nruter{)(ssorcao noitcnuf( + dee" ascii
    $s2 = "xelft rav\\n;\"t76x\\\\\" = modnart rav\\n;)5(]\"\"+\"47x\\\\\"+\"Arahc\"[keppelt = deerdt rav;\"Xhhzfal8\" = keppelt rav'[\"spl" ascii
    $s3 = "pell noitcnuf\\n;\"nepf6x\\\\\" = modnarl rav\\n;\"y47x\\\\\" = deerdl rav\\n;\"e07x\\\\\" = sdnetl rav\\n;\"ti27x\\\\w\" = cthl" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}