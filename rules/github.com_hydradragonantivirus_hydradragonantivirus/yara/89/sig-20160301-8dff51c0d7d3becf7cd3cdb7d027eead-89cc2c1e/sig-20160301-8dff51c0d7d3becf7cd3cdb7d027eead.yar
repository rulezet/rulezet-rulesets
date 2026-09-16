rule sig_20160301_8dff51c0d7d3becf7cd3cdb7d027eead {
  meta:
    description = "datamaliciousorder - file 20160301_8dff51c0d7d3becf7cd3cdb7d027eead.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7142a21ee663ad35bde338f8381abadae786963d3053cee3d930aba9a71e68b0"

  strings:
    $s1 = "componentOriginal[(\"\\u0070ort\", \"b\" + \"\\u0075\\u0073\", \"r\" + \"u\\u0069n\", \"\\u0061rg\\u0075\" + \"ment\", \"w\\u007" ascii
    $s2 = "while(epilogueDeformation[(\"r\\u0065\\u0061\\u0064y\" + \"s\\u0074\\u0061t\" + \"e\")] < ((1 + 1) * (26 / 13))) {" fullword ascii
    $s3 = "realFinish = (((47 - 39) - 7), this);" fullword ascii
    $s4 = "} catch(shockCommand) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}