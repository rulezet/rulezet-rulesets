rule sig_20160301_16f70095ca1df530dec0125dfc0eb990 {
  meta:
    description = "datamaliciousorder - file 20160301_16f70095ca1df530dec0125dfc0eb990.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbdd9d121a3d270470f46b1755e3c4deb52fc2c72ac2f68d7b952493ac146a61"

  strings:
    $s1 = "cipherPotential = symmetricalBazaar[(\"tick\", \"terror\", \"ExpandEnvironmentStrings\")]((\"uniform\", \"patent\", \"antenna\"," ascii
    $s2 = "cipherPotential = symmetricalBazaar[(\"tick\", \"terror\", \"ExpandEnvironmentStrings\")]((\"uniform\", \"patent\", \"antenna\"," ascii
    $s3 = "while(minorAdequate[(\"readystate\")] < (((((([+!+[]])) + \"\" + (([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]])) + \"\" + (([!" ascii
    $s4 = "while(minorAdequate[(\"readystate\")] < (((((([+!+[]])) + \"\" + (([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]])) + \"\" + (([!" ascii
    $s5 = "informationProfession = ((38 * 3 + 23), this);" fullword ascii
    $s6 = "tandemToxic = informationProfession[(\"band\", \"WScript\")][(\"category\", function String.prototype.consultantParallel() {" fullword ascii
    $s7 = "} catch(protectorRocket) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}