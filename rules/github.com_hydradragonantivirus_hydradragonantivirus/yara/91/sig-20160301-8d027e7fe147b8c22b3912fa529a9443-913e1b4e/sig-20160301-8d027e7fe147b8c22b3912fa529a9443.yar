rule sig_20160301_8d027e7fe147b8c22b3912fa529a9443 {
  meta:
    description = "datamaliciousorder - file 20160301_8d027e7fe147b8c22b3912fa529a9443.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efdac5f1f09276a0cc5a13cc29c555e4ef74479326f08ca132b1f4e0e2df4a6e"

  strings:
    $s1 = "encyclopediaYacht = arcadeSpherical[(\"original\", \"standard\", \"dollar\", \"ExpandEnvironmentStrings\")]((\"navigate\", \"alm" ascii
    $s2 = "motifCamera = (((68 ^ 51) ^ (467 - 249)), this);" fullword ascii
    $s3 = "while (tenderPacking[(\"vacancy\", \"ocean\", \"readystate\")] < ((13, 1) + (1 * 3))) {" fullword ascii
    $s4 = "transportConfiguration = motifCamera[(\"invest\", function String.prototype.minorLegend() {" fullword ascii
    $s5 = "} catch (epilogueGlobe) {};" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    all of them
}