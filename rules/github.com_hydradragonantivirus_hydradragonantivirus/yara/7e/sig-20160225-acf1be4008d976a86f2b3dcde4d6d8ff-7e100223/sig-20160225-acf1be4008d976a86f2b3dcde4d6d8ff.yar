rule sig_20160225_acf1be4008d976a86f2b3dcde4d6d8ff {
  meta:
    description = "datamaliciousorder - file 20160225_acf1be4008d976a86f2b3dcde4d6d8ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bab8eb354662f8073f35626cd186b813511cb2a99db1dbbcb894f41c07f367d"

  strings:
    $s1  = "    var denouementtxN = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2  = "function btoa(gauntoHC, factiousWWt, repealfOX, bemusedKKO, monetaryCu6, hummockNKM, commiserateeBd, furnishmuy, considerIRw, ve" ascii
    $s3  = "function btoa(gauntoHC, factiousWWt, repealfOX, bemusedKKO, monetaryCu6, hummockNKM, commiserateeBd, furnishmuy, considerIRw, ve" ascii
    $s4  = "        return WScript[bemusedyUs](refractoryYzu);" fullword ascii
    $s5  = "    return ideologyQlg;" fullword ascii
    $s6  = "var unmitigatedqeC = function() {" fullword ascii
    $s7  = "    btoa(gauntoHC, factiousWWt, repealfOX, bemusedKKO, monetaryCu6, hummockNKM, commiserateeBd, furnishmuy, considerIRw, vestige" ascii
    $s8  = "    return treadF9y;" fullword ascii
    $s9  = "    treadF9y.prototype.fOg6Ar3IKA = function(refractoryYzu) {" fullword ascii
    $s10 = "    treadF9y.prototype.spbhIou0H8 = function(refractoryYzu) {" fullword ascii
    $s11 = "    var treadF9y = function() {" fullword ascii
    $s12 = "var nuancehGa = function(pontificalfxV) {" fullword ascii
    $s13 = "            pathologicalUh8.open(nuancehGa([ 327, 157, 228 ]), sententiousMRp, false);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}