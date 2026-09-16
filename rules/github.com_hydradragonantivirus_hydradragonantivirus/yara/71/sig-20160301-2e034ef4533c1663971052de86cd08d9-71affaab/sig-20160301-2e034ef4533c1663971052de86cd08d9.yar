rule sig_20160301_2e034ef4533c1663971052de86cd08d9 {
  meta:
    description = "datamaliciousorder - file 20160301_2e034ef4533c1663971052de86cd08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681e656ca82ad6040ab3606009c038658969ec27e411fd1ab6eedfe380f08415"

  strings:
    $s1 = "while(legendSignal[(\"\\u0073e\\u0078\\u0075\" + \"\\u0061\\u006c\", \"su\\u0062\" + \"\\u006a\" + \"ect\\u0069ve\", \"rea\" + " ascii
    $s2 = "investTransport[(\"\\u006da\\u0072\\u006b\", \"s\\u0061\\u0074\" + \"\\u0065lli\\u0074\\u0065\", \"e\\u0078t\\u0072\\u0061\\u006" ascii
    $s3 = "while(legendSignal[(\"\\u0073e\\u0078\\u0075\" + \"\\u0061\\u006c\", \"su\\u0062\" + \"\\u006a\" + \"ect\\u0069ve\", \"rea\" + " ascii
    $s4 = "investTransport = ((([+!+[]])), this);" fullword ascii
    $s5 = "} catch(provisionParadox) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}