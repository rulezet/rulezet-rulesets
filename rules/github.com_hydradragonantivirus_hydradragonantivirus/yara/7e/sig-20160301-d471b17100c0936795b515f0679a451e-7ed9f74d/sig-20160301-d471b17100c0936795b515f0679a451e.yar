rule sig_20160301_d471b17100c0936795b515f0679a451e {
  meta:
    description = "datamaliciousorder - file 20160301_d471b17100c0936795b515f0679a451e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1650f631a3fe9a630c10dc8286805059c57b16e8827c4b511633f9bc6b61ea6f"

  strings:
    $s1 = "packingAmphibian = (((2 / 2) * 1), this);" fullword ascii
    $s2 = "provinceCycle[(\"\\u0061u\\u0074\\u0068\" + \"ori\\u0074\" + \"y\", \"s\" + \"\\u0061v\\u0065T\" + \"\\u006f\" + \"\\u0046\" + " ascii
    $s3 = "Culture, ((2 ^ 0) + (0 + 0)));" fullword ascii
    $s4 = "while(provocationAccompany[(\"rea\" + \"\\u0064y\" + \"\\u0073t\\u0061\\u0074e\")] < (0 | (([!+[] + !+[]]) * ([!+[] + !+[]])))) " ascii
    $s5 = "packingAmphibian[(\"c\\u006fm\" + \"\\u0070ut\\u0065\\u0072\", function String.prototype.televisionCategory() {" fullword ascii
    $s6 = "} catch(principleClub) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    all of them
}