rule sig_20160526_0c27efb105ffcb4882b83b9b4bf0ba1d {
  meta:
    description = "datamaliciousorder - file 20160526_0c27efb105ffcb4882b83b9b4bf0ba1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "103e1f3d0e33d3e31fc8a69d367ef6be762f607c69066b2286108610c3af5826"

  strings:
    $s1  = "function qfnobzGl(LRXOiZhHQNHad) {var MbpGMSR = EvjIzmwuy.join(bnvTfHsB[0]);var RkRlXG, NjuFPmHQjgePdFSfuVE, JddcV, HsqhDFYgwTTX" ascii
    $s2  = "zmnaZsQCQaTzaf += ig(RkRlXG);else if (YyWWxxKT == (1053 + Math.round((Math.pow(Math.sin(285), 2) + Math.pow(Math.cos(285), 2) - " ascii
    $s3  = "function MDgBwiSSSBiqJwfbEd(raGHwxxgpMrEHfsR,oWarHKTUMT){return raGHwxxgpMrEHfsR.charAt(oWarHKTUMT);}" fullword ascii
    $s4  = "function qfnobzGl(LRXOiZhHQNHad) {var MbpGMSR = EvjIzmwuy.join(bnvTfHsB[0]);var RkRlXG, NjuFPmHQjgePdFSfuVE, JddcV, HsqhDFYgwTTX" ascii
    $s5  = "function ig(fEImqZgUnVewwSwZZ){return String.fromCharCode(fEImqZgUnVewwSwZZ);}" fullword ascii
    $s6  = "function cvwzmiDTe(XfJNDlfbhjAuyXHXQi,dybYzWeJqbZQBOcOHyqVXsoz){return XfJNDlfbhjAuyXHXQi.indexOf(dybYzWeJqbZQBOcOHyqVXsoz);}" fullword ascii
    $s7  = "function BHWzWyEwIRaoUXvd(zEWiY,rleahtVfla,DFuNPeKXbO){return String.fromCharCode(zEWiY,rleahtVfla,DFuNPeKXbO);}" fullword ascii
    $s8  = " NjuFPmHQjgePdFSfuVE, JddcV);} while (xtjWdO < LRXOiZhHQNHad.length);return zmnaZsQCQaTzaf;}" fullword ascii
    $s9  = "function cUMJrqAzIljSfBCvSFhKBaP(OEsgCmhscDDKlVRTJH,cutuBcwfcYnCcRUC){return String.fromCharCode(OEsgCmhscDDKlVRTJH,cutuBcwfcYnC" ascii
    $s10 = "1))-989)) zmnaZsQCQaTzaf += cUMJrqAzIljSfBCvSFhKBaP(RkRlXG, NjuFPmHQjgePdFSfuVE);else zmnaZsQCQaTzaf += BHWzWyEwIRaoUXvd(RkRlXG," ascii
    $s11 = "function cUMJrqAzIljSfBCvSFhKBaP(OEsgCmhscDDKlVRTJH,cutuBcwfcYnCcRUC){return String.fromCharCode(OEsgCmhscDDKlVRTJH,cutuBcwfcYnC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}