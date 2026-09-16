rule sig_20160301_2c49482b04a16eec305ff3e42637e500 {
  meta:
    description = "datamaliciousorder - file 20160301_2c49482b04a16eec305ff3e42637e500.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d2e1f643e23ebd34cb88be006aef1782d2e510e082beffd13b0a86c137a9005"

  strings:
    $s1 = "realAmmunition = ((1 + (0 | 0)), this);" fullword ascii
    $s2 = "while(amorphousMechanic[(\"rea\\u0064\" + \"y\\u0073tat\\u0065\")] < (2 * 2 & (1 * 7))) {" fullword ascii
    $s3 = "amorphousMechanic = realAmmunition[(\"fo\" + \"r\\u0074u\" + \"n\\u0065\", \"\\u0072ac\" + \"\\u0065\", function String.prototyp" ascii
    $s4 = "amorphousMechanic = realAmmunition[(\"fo\" + \"r\\u0074u\" + \"n\\u0065\", \"\\u0072ac\" + \"\\u0065\", function String.prototyp" ascii
    $s5 = "} catch(emissionAtom) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}