rule sig_20160301_d3af2272a540626f4485c42af3616fa6 {
  meta:
    description = "datamaliciousorder - file 20160301_d3af2272a540626f4485c42af3616fa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eab30d6f97f4e256fe03a69657e16f87c2df1ea58be0cd3a168e894f3ea2375"

  strings:
    $s1 = "elementVibration = recordFlag[(\"machine\", \"audience\", \"momentum\", \"cocoon\", \"ExpandEnvironmentStrings\")]((\"mile\", \"" ascii
    $s2 = "elementVibration = recordFlag[(\"machine\", \"audience\", \"momentum\", \"cocoon\", \"ExpandEnvironmentStrings\")]((\"mile\", \"" ascii
    $s3 = "while (seasonAutonomy[(\"readystate\")] < ((0 - 0) | 2 * 2)) {" fullword ascii
    $s4 = "netAction = ((1, 197, 203, 2) * (244 / 4), this);" fullword ascii
    $s5 = "seasonAutonomy[(\"open\")]((\"infinitive\", \"arsenal\", \"invest\", \"portal\", function String.prototype.containerNorm() {" fullword ascii
    $s6 = "} catch (statisticalModern) {};" fullword ascii

  condition:
    uint16(0) == 0x656e and
    all of them
}