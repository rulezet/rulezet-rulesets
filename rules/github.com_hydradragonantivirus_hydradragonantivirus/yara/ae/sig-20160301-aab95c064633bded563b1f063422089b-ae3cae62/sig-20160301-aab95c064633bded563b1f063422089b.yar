rule sig_20160301_aab95c064633bded563b1f063422089b {
  meta:
    description = "datamaliciousorder - file 20160301_aab95c064633bded563b1f063422089b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbbfbc548267e77c415881fc2bb8d7078fb3f59a5655a9904ef55331d18682a5"

  strings:
    $s1 = "modifyExport = cultureAgent[(\"\\u0073\" + \"t\\u0061ti\\u006f\\u006e\", function String.prototype.absorptionDiction() {" fullword ascii
    $s2 = "cultureAgent = ((71, 32, 77, 1), this);" fullword ascii
    $s3 = "while (sabotageCopy[(\"\\u0072e\\u0061\\u0064y\" + \"\\u0073t\\u0061t\\u0065\")] < ((4 ^ 0) ^ 0)) {" fullword ascii
    $s4 = "} catch (distantQualification) {};" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    all of them
}