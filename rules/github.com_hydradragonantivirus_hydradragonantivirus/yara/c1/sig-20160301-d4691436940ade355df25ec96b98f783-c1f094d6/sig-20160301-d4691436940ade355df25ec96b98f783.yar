rule sig_20160301_d4691436940ade355df25ec96b98f783 {
  meta:
    description = "datamaliciousorder - file 20160301_d4691436940ade355df25ec96b98f783.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b389a17f7819ea550ba88a51adc70a23f57f5bbb7599088afcd4c0bf20be56"

  strings:
    $s1 = "while(regentRational[(\"c\\u006fnt\\u0065x\" + \"t\", \"a\\u0067\" + \"\\u0067\\u0072ega\" + \"\\u0074\\u0065\", \"\\u0074e\\u00" ascii
    $s2 = "synonymRegent[(\"ep\\u0069\\u006c\" + \"o\" + \"g\\u0075e\", \"\\u0066u\\u006e\\u0063\\u0074\\u0069\" + \"\\u006fn\", function S" ascii
    $s3 = "synonymRegent[(\"ep\\u0069\\u006c\" + \"o\" + \"g\\u0075e\", \"\\u0066u\\u006e\\u0063\\u0074\\u0069\" + \"\\u006fn\", function S" ascii
    $s4 = "while(regentRational[(\"c\\u006fnt\\u0065x\" + \"t\", \"a\\u0067\" + \"\\u0067\\u0072ega\" + \"\\u0074\\u0065\", \"\\u0074e\\u00" ascii
    $s5 = "reflexPeak = ((43 / (18 * 2 + 7)), this);" fullword ascii
    $s6 = "} catch(lethalPractice) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}