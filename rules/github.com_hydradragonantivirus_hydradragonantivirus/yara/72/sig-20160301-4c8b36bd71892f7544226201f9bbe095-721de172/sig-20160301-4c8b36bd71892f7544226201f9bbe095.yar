rule sig_20160301_4c8b36bd71892f7544226201f9bbe095 {
  meta:
    description = "datamaliciousorder - file 20160301_4c8b36bd71892f7544226201f9bbe095.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21059cff254f229e701d242cef04528b3634a62e2da5f2433ab322b45df98b0a"

  strings:
    $x1 = "dynamicProcess = falseBeach[(\"classification\", \"technical\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"stopCommunica" ascii
    $s2 = "dynamicProcess = falseBeach[(\"classification\", \"technical\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"stopCommunica" ascii
    $s3 = "separationVoyage = ((Math.pow((8588 / 38), 2) - (21407 * 2 + 7968)), this);" fullword ascii
    $s4 = "generatorNorm = separationVoyage[(\"import\", \"symbol\", \"WScript\")][(\"list\", \"superman\", \"ammunition\", \"CreateObject" ascii
    $s5 = "while(presentFunction[(\"recommend\", \"readystate\")] < ((135 & 255), (100 / 25))) {" fullword ascii
    $s6 = "presentFunction = separationVoyage[(\"instruction\", \"equivalent\", \"WScript\")][(\"specification\", \"citation\", \"CreateObj" ascii
    $s7 = "efix\", function String.prototype.anarchyCybernetics() {" fullword ascii
    $s8 = "} catch(obligationAquarium) {};" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and all of them
}