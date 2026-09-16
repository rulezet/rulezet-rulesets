rule sig_20160301_3d3d3d54ea02dd96338f6e4a8d35e2d9 {
  meta:
    description = "datamaliciousorder - file 20160301_3d3d3d54ea02dd96338f6e4a8d35e2d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adc453f4a1e68d6faae73ffa956fb510351f614c92b66b71c37a6e1219686d41"

  strings:
    $s1 = "while (testIsolate[(\"p\" + \"\\u0072of\\u0069\" + \"l\" + \"e\", \"\\u0069\\u006e\\u0074\\u0065\\u0072v\" + \"\\u0061\\u006c\"," ascii
    $s2 = "6c\" + \"\\u0065\\u0076\" + \"\\u0069\\u0073i\\u006f\" + \"n\") + (\"\\u006d\\u0075s\\u0065\\u0075\\u006d\", function String.pro" ascii
    $s3 = "while (testIsolate[(\"p\" + \"\\u0072of\\u0069\" + \"l\" + \"e\", \"\\u0069\\u006e\\u0074\\u0065\\u0072v\" + \"\\u0061\\u006c\"," ascii
    $s4 = "declarationPreamble = ((1 & (0 | 1)), this);" fullword ascii
    $s5 = "aquariumStory = legionSupermarket[(\"ma\\u0073\" + \"siv\\u0065\", \"\\u0045\\u0078p\\u0061\" + \"\\u006e\" + \"\\u0064\\u0045" ascii
    $s6 = "Colossal() {" fullword ascii
    $s7 = "} catch (secretCentral) {};" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}