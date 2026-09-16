rule sig_20160301_f630378837c37fc043a621170e8b7d2f {
  meta:
    description = "datamaliciousorder - file 20160301_f630378837c37fc043a621170e8b7d2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f070539fe078bebfeafe58af31b46d4b5fcb8282e1526a78a8c2dbf799ce2d"

  strings:
    $s1 = "while(amplitudeReaction[(\"\\u0074\\u0072\\u0069\\u0062u\" + \"n\\u0065\", \"i\\u006et\\u0065rv\" + \"a\\u006c\", \"b\" + \"a\\u" ascii
    $s2 = "while(amplitudeReaction[(\"\\u0074\\u0072\\u0069\\u0062u\" + \"n\\u0065\", \"i\\u006et\\u0065rv\" + \"a\\u006c\", \"b\" + \"a\\u" ascii
    $s3 = "businessIndex = ((0 + 1), this);" fullword ascii
    $s4 = "handicapTotal[(\"for\\u006d\" + \"\\u0061l\", \"d\\u0065\\u0063\\u0061\\u0064\\u0065\", function String.prototype.ammunitionNose" ascii
    $s5 = "} catch(apparatusParity) {};" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    all of them
}