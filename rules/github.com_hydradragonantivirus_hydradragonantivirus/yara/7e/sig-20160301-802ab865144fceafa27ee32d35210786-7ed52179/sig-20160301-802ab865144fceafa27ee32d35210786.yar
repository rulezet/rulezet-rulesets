rule sig_20160301_802ab865144fceafa27ee32d35210786 {
  meta:
    description = "datamaliciousorder - file 20160301_802ab865144fceafa27ee32d35210786.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6c11be5c681abaf66d1d34df79dc2fd5fd3c843e62c223aac25badaade4c48"

  strings:
    $s1 = "autographInjection = (((([!+[] + !+[]])) | (56 & 49)), this);" fullword ascii
    $s2 = "republicInjection = autographInjection[(\"WSc\\u0072ip\\u0074\")][(\"\\u0063e\\u0072tif\\u0069\\u0063\\u0061\\u0074e\", \"\\u006" ascii
    $s3 = "while (circleIdentical[(\"do\\u0063\\u0075\\u006d\\u0065n\\u0074a\\u0072y\", \"r\\u0065adys\\u0074\\u0061te\")] < ((23 - 23) ^ (" ascii
    $s4 = "072\\u0065c\\u0069\\u0073\\u0069o\\u006e\", \"\\u006c\\u0069\\u006e\\u0067uist\", function String.prototype.groupColony() {" fullword ascii
    $s5 = "} catch (tenderInform) {};" fullword ascii

  condition:
    uint16(0) == 0x7561 and
    all of them
}