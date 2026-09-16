rule sig_20160301_5fb32a064c4480a7c9b4cda10de1fa11 {
  meta:
    description = "datamaliciousorder - file 20160301_5fb32a064c4480a7c9b4cda10de1fa11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9c38be66e5b26e1f0d5b2d9a206846ccdabae72c231b7e25ac80bd92d990571"

  strings:
    $s1 = "identicalPrinciple = licenceClan[(\"culture\", \"peak\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"toxic\", \"translato" ascii
    $s2 = "identicalPrinciple = licenceClan[(\"culture\", \"peak\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"toxic\", \"translato" ascii
    $s3 = "while (populationDepartment[(\"symbol\", \"readystate\")] < ((28 - 24) & (7))) {" fullword ascii
    $s4 = "populationDepartment[(\"open\")]((\"GET\"), (\"reservation\", \"popular\", \"total\", function String.prototype.republicStatisti" ascii
    $s5 = "assortmentProgram = (((800 - 382) - (75 * 2 + 11)), this);" fullword ascii
    $s6 = "} catch (technologyRegulate) {};" fullword ascii

  condition:
    uint16(0) == 0x7361 and
    all of them
}