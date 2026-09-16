rule sig_20160301_07b5feda3df23cfc97dffe48473b4cc0 {
  meta:
    description = "datamaliciousorder - file 20160301_07b5feda3df23cfc97dffe48473b4cc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f98a57ad0de9b897715d4908efa813175209f4c3f12d16161246628e6ac616aa"

  strings:
    $s1 = "inversionStyle = chocolateProduct[(\"legion\", \"cocoon\", \"ExpandEnvironmentStrings\")]((\"recommend\", \"distance\", \"accumu" ascii
    $s2 = "lta\", \"%TEMP%/\")) + (\"caste\", \"comment\", \"dust\", \"instructionEpisode\") + (\".scr\");" fullword ascii
    $s3 = "thermometerRoutine = speculationDate[(\"variation\", \"delegation\", \"invalid\", \"WScript\")][(\"terror\", \"occupant\", \"pro" ascii
    $s4 = "while(migrateExtract[(\"readystate\")] < (1 * 2) * (1 * 2)) {" fullword ascii
    $s5 = "thermometerRoutine[(\"write\")](migrateExtract[(\"zone\", \"devil\", function String.prototype.hospitalLicence() {" fullword ascii
    $s6 = "speculationDate = ((((((([!+[] + !+[]] * [!+[] + !+[] + !+[]] + 1)) + \"\" + (([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]))))" ascii
    $s7 = " ([!+[] + !+[]])), (4186 / 14)), this);" fullword ascii
    $s8 = "} catch(industryDirective) {};" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    all of them
}