rule sig_20160301_dd12ffbf04ee8ba6b3a4925af8fac1d2 {
  meta:
    description = "datamaliciousorder - file 20160301_dd12ffbf04ee8ba6b3a4925af8fac1d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ecd86dd0b615488e42322abc8202301989ca25ab2381b5340d351894080a84"

  strings:
    $s1 = "while(guideSabotage[(\"\\u0061n\" + \"\\u0065\\u0063\\u0064\" + \"ot\\u0065\", \"c\" + \"om\\u0070\" + \"an\" + \"y\", \"\\u0076" ascii
    $s2 = "spindleBureaucracy = (((232 / 29) - (Math.pow(12, 2) - 137)), this);" fullword ascii
    $s3 = "guideSabotage = spindleBureaucracy[(\"\\u0057S\\u0063\" + \"\\u0072ip\\u0074\")][(\"\\u0076\" + \"\\u0069o\\u006cet\", \"\\u0061" ascii
    $s4 = "6f\" + \"\\u0067\\u0079\", \"\\u0074e\" + \"\\u0063hn\\u0069\" + \"\\u0071u\\u0065\", function String.prototype.maskStrategic() " ascii
    $s5 = "while(guideSabotage[(\"\\u0061n\" + \"\\u0065\\u0063\\u0064\" + \"ot\\u0065\", \"c\" + \"om\\u0070\" + \"an\" + \"y\", \"\\u0076" ascii
    $s6 = "} catch(provocationBarge) {};" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    all of them
}