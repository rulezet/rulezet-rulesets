rule sig_20160301_6cb51704f3cc9d914e18d64858621c93 {
  meta:
    description = "datamaliciousorder - file 20160301_6cb51704f3cc9d914e18d64858621c93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4970f8b7c7ddeb5e9380c031f96a10047ab42cd560eafb24644b71e3208fb1f8"

  strings:
    $s1 = "imitateSymptom = commandIdentical[(\"\\u0069m\" + \"\\u0070or\\u0074\", \"com\\u0070\" + \"act\", \"dess\" + \"\\u0065r\\u0074\"" ascii
    $s2 = "commandIdentical = (((6 * 3 + 5) / (4 * 5 + 3)), this);" fullword ascii
    $s3 = "while (imitateSymptom[(\"no\" + \"\\u0073\\u0065\", \"r\\u0065\" + \"ad\\u0079s\\u0074a\" + \"t\\u0065\")] < ((4 & 7) + (0 / 35)" ascii
    $s4 = "\"us\", \"i\\u006d\\u0070\\u006f\\u0072t\", function String.prototype.integralHobby() {" fullword ascii
    $s5 = "} catch (diskNet) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}