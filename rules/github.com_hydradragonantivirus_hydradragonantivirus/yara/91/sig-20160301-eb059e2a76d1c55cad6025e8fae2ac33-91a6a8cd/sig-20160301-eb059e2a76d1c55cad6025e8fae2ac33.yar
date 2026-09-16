rule sig_20160301_eb059e2a76d1c55cad6025e8fae2ac33 {
  meta:
    description = "datamaliciousorder - file 20160301_eb059e2a76d1c55cad6025e8fae2ac33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a82ea593de0246fe43b54b136d067467615aee2d569fa75e183424f42b88270"

  strings:
    $s1 = "legendParadox = ((2 * 3 * 7 * 2 + (1209 / 31)), this);" fullword ascii
    $s2 = "while (projectionAspect[(\"\\u0070a\\u0073te\", \"\\u006ce\\u0067en\\u0064\", \"\\u0065\\u006ee\\u0072g\\u0079\", \"r\\u0065\\u0" ascii
    $s3 = "projectionAspect[(\"\\u006fr\\u0064er\", function String.prototype.personPublic() {" fullword ascii
    $s4 = "while (projectionAspect[(\"\\u0070a\\u0073te\", \"\\u006ce\\u0067en\\u0064\", \"\\u0065\\u006ee\\u0072g\\u0079\", \"r\\u0065\\u0" ascii
    $s5 = "} catch (signalIsolate) {};" fullword ascii

  condition:
    uint16(0) == 0x656c and
    all of them
}