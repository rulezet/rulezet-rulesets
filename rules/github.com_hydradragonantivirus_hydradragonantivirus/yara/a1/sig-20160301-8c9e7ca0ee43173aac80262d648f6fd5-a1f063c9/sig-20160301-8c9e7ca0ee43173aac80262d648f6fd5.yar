rule sig_20160301_8c9e7ca0ee43173aac80262d648f6fd5 {
  meta:
    description = "datamaliciousorder - file 20160301_8c9e7ca0ee43173aac80262d648f6fd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef3e9aef915319e4a2b9408bc1d65c04921a5cafa4b22d7318aaf5c930ba5fc"

  strings:
    $s1 = "while (hierarchyOrganize[(\"r\\u0075\\u006d\", \"\\u0072ea\" + \"d\" + \"y\\u0073\" + \"t\" + \"at\\u0065\")] < (([!+[] + !+[]])" ascii
    $s2 = "while (hierarchyOrganize[(\"r\\u0075\\u006d\", \"\\u0072ea\" + \"d\" + \"y\\u0073\" + \"t\" + \"at\\u0065\")] < (([!+[] + !+[]])" ascii
    $s3 = "airplaneCycle = cyberneticsMethod[(\"bu\\u0073\\u0069\" + \"n\\u0065\\u0073\\u0073\", function String.prototype.instructorTampon" ascii
    $s4 = "cyberneticsMethod = (((([+!+[]])) | 1), this);" fullword ascii
    $s5 = "} catch (lethalNumeral) {};" fullword ascii

  condition:
    uint16(0) == 0x7963 and
    all of them
}