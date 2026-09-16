rule sig_20160301_5403dc78710d735092c5f29cedd043be {
  meta:
    description = "datamaliciousorder - file 20160301_5403dc78710d735092c5f29cedd043be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e280d21efd39da2ec3e32bb9cb51d378c44fcf5720abcf0aa7c96e0a10b2886"

  strings:
    $s1 = "firmUniversal = cathedralPseudonym[(\"logic\", \"ExpandEnvironmentStrings\")]((\"club\", \"%TEMP%/\")) + (\"expert\", \"director" ascii
    $s2 = "firmUniversal = cathedralPseudonym[(\"logic\", \"ExpandEnvironmentStrings\")]((\"club\", \"%TEMP%/\")) + (\"expert\", \"director" ascii
    $s3 = "juniorTropical = ((Math.pow(5 * 17, (8 / 4)) - (13485 - 6309)), this);" fullword ascii
    $s4 = "while(paradoxAlmanac[(\"product\", function String.prototype.ruinGrammar() {" fullword ascii
    $s5 = "} catch(personSeason) {};" fullword ascii

  condition:
    uint16(0) == 0x756a and
    all of them
}