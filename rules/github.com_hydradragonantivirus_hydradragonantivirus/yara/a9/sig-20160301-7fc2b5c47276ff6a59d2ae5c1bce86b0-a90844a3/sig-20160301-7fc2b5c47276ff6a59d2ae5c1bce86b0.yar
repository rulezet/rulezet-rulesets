rule sig_20160301_7fc2b5c47276ff6a59d2ae5c1bce86b0 {
  meta:
    description = "datamaliciousorder - file 20160301_7fc2b5c47276ff6a59d2ae5c1bce86b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f982377d092253376adb6d23b720ff0a1e5048daeaf46d82748a4be27504a595"

  strings:
    $s1 = "prospectProject = (((31 - 31) + (2 - 1)), this);" fullword ascii
    $s2 = "intellectVisa = prospectProject[(\"t\\u0072a\\u0064i\" + \"\\u0074ion\", \"\\u0061\\u006dmu\" + \"\\u006eit\" + \"i\\u006fn\", f" ascii
    $s3 = "while (showGlobe[(\"\\u0072\\u0065\\u0061d\" + \"\\u0079\\u0073tat\" + \"\\u0065\")] < ((150 / 30) & (([!+[] + !+[]]) * ([!+[] +" ascii
    $s4 = "intellectVisa = prospectProject[(\"t\\u0072a\\u0064i\" + \"\\u0074ion\", \"\\u0061\\u006dmu\" + \"\\u006eit\" + \"i\\u006fn\", f" ascii
    $s5 = "while (showGlobe[(\"\\u0072\\u0065\\u0061d\" + \"\\u0079\\u0073tat\" + \"\\u0065\")] < ((150 / 30) & (([!+[] + !+[]]) * ([!+[] +" ascii
    $s6 = "} catch (experimentThermometer) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}