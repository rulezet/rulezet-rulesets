rule sig_20160301_de7309b36a1f2e46797af0c382e5bfdf {
  meta:
    description = "datamaliciousorder - file 20160301_de7309b36a1f2e46797af0c382e5bfdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5313a48857ab294710807c98065ea14d252e4192e77a88927d31ca4f69b08c1"

  strings:
    $s1 = "imitationAlternative = diplomaFinal[(\"c\\u006f\\u006cl\" + \"is\\u0069\\u006f\\u006e\", \"\\u0072\" + \"\\u0065a\" + \"\\u006c" ascii
    $s2 = "+ \"\\u0074\")]((\"nu\\u006d\" + \"e\\u0072\" + \"\\u0061l\", function String.prototype.essayOperation() {" fullword ascii
    $s3 = "diplomaFinal = (((([+[]])) ^ (18 - 17)), this);" fullword ascii
    $s4 = "while (imitationAlternative[(\"\\u0061\\u006c\\u006dan\" + \"\\u0061c\", \"\\u0072\\u0065a\\u0064y\\u0073\" + \"\\u0074\\u0061\"" ascii
    $s5 = "while (imitationAlternative[(\"\\u0061\\u006c\\u006dan\" + \"\\u0061c\", \"\\u0072\\u0065a\\u0064y\\u0073\" + \"\\u0074\\u0061\"" ascii
    $s6 = "} catch (cortegeDog) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}