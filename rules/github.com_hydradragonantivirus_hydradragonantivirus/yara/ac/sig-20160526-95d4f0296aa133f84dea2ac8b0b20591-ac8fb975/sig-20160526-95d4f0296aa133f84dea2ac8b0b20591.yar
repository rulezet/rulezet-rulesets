rule sig_20160526_95d4f0296aa133f84dea2ac8b0b20591 {
  meta:
    description = "datamaliciousorder - file 20160526_95d4f0296aa133f84dea2ac8b0b20591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a4d25c05dac2cc936feff8d610c8ecc8fd529b4e4a4ce08138b735dfbbd940"

  strings:
    $s1 = "e+dnenoisilloce ,suidarelcitrape+gsme + eixode+imd+rerednerd+cthd + tsilslianbmuhtod+ssorcad + sdnetd+))(};modnard nruter{)(deer" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}