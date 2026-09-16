rule sig_20160301_47e4625d5909fd2d4af1f0fcd3c786a6 {
  meta:
    description = "datamaliciousorder - file 20160301_47e4625d5909fd2d4af1f0fcd3c786a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc17bfbe6257b332db2c18b22ab31d688e8e2a70121aeb76c8aa7b4ea7165eed"

  strings:
    $s1 = "individualityCharm[(\"pr\" + \"\\u006f\\u0070\\u006f\" + \"r\\u0074\\u0069on\\u0061\" + \"\\u006c\", \"S\\u006c\\u0065\\u0065p\"" ascii
    $s2 = "reflectionSponsor[(\"\\u0069\\u006ee\" + \"\\u0072t\", function String.prototype.effectSession() {" fullword ascii
    $s3 = "while(instructorTick[(\"\\u0072\\u0065a\" + \"d\" + \"ys\\u0074\\u0061\\u0074\\u0065\")] < (2 * 11 * 3 * 2 / (([!+[] + !+[] + !+" ascii
    $s4 = "while(instructorTick[(\"\\u0072\\u0065a\" + \"d\" + \"ys\\u0074\\u0061\\u0074\\u0065\")] < (2 * 11 * 3 * 2 / (([!+[] + !+[] + !+" ascii
    $s5 = "passNavigate = ((([+!+[]])), this);" fullword ascii
    $s6 = "} catch(reasonPrinciple) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    all of them
}