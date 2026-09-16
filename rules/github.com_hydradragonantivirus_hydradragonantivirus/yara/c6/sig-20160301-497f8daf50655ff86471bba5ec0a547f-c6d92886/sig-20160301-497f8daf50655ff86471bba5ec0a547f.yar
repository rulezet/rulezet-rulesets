rule sig_20160301_497f8daf50655ff86471bba5ec0a547f {
  meta:
    description = "datamaliciousorder - file 20160301_497f8daf50655ff86471bba5ec0a547f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668d356784d285d2a8cf8cce047b39831cd921d2bd96dde5c1a5b2b7621eaf1b"

  strings:
    $s1 = "legendPassive = transcriptionTranslator[(\"m\\u0065d\" + \"\\u0061\\u006c\", \"WS\" + \"\\u0063\" + \"\\u0072\\u0069\\u0070t\")]" ascii
    $s2 = "transcriptionTranslator = (((1 * 1) + (123, 248, 85, 0)), this);" fullword ascii
    $s3 = "while (schemeExtract[(\"\\u0070\" + \"r\\u0065\\u0073\\u0075m\" + \"pt\\u0069\" + \"\\u006f\\u006e\", \"\\u0074\\u0072\\u0061\\u" ascii
    $s4 = "while (schemeExtract[(\"\\u0070\" + \"r\\u0065\\u0073\\u0075m\" + \"pt\\u0069\" + \"\\u006f\\u006e\", \"\\u0074\\u0072\\u0061\\u" ascii
    $s5 = "i\\u0073\" + \"\\u0069\\u006f\" + \"\\u006e\", function String.prototype.limitAbsolute() {" fullword ascii
    $s6 = "} catch (collectorAmputate) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}