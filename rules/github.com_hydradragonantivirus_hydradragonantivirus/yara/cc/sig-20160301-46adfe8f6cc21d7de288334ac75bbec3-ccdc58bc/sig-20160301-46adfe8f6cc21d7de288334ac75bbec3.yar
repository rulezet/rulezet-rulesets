rule sig_20160301_46adfe8f6cc21d7de288334ac75bbec3 {
  meta:
    description = "datamaliciousorder - file 20160301_46adfe8f6cc21d7de288334ac75bbec3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "672b29c09514c983b47b62d73f57fccf7c9477f56527c9efd6ddbaf37fd82d4b"

  strings:
    $s1 = "while (iconLogic[(\"c\\u0061\\u0072\\u0064\\u0069\\u006e\\u0061l\", \"a\\u0072\\u0067\\u0075m\\u0065\\u006e\\u0074\", \"ba\\u006" ascii
    $s2 = "while (iconLogic[(\"c\\u0061\\u0072\\u0064\\u0069\\u006e\\u0061l\", \"a\\u0072\\u0067\\u0075m\\u0065\\u006e\\u0074\", \"ba\\u006" ascii
    $s3 = "portraitTransplant = symbolTranslation[(\"\\u0069ntelli\\u0067\\u0065n\\u0063\\u0065\", \"\\u0068is\\u0074or\\u0079\", \"\\u0045" ascii
    $s4 = "\\u0064En\\u0076\\u0069\\u0072o\\u006e\\u006de\\u006e\\u0074St\\u0072\\u0069ng\\u0073\")]((\"\\u0072\\u0065fle\\u0078\", functio" ascii
    $s5 = "academyCollective = (((0 ^ 0) | (76 * 2 + 24)), this);" fullword ascii
    $s6 = "} catch (relaxationMeridian) {};" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    all of them
}