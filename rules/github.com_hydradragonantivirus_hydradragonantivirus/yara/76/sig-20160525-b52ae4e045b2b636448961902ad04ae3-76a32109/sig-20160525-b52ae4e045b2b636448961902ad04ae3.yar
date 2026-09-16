rule sig_20160525_b52ae4e045b2b636448961902ad04ae3 {
  meta:
    description = "datamaliciousorder - file 20160525_b52ae4e045b2b636448961902ad04ae3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1943126ff422e33f2aa1596dd7089e6a7c0734b23942e9669c65235a35b7606f"

  strings:
    $s1 = "odnarj + ))(};ecapsetihwxelfj nruter{)(sdnetj noitcnuf( + ))(};keppelj nruter{)(deerdj noitcnuf( ,mj + dnenoisillocj + ))(};suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}