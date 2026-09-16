rule sig_20160525_8170322e2ce3a323fe8bb96decfcaa56 {
  meta:
    description = "datamaliciousorder - file 20160525_8170322e2ce3a323fe8bb96decfcaa56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09195494e393535f45aa0bac5e9c44ffd2b2ba56fda5b3effbe8916a111d2ba7"

  strings:
    $s1  = "w(Math.cos(546), 2) - 1))-992)) qwzwBkJCjlGyMfczp += SkcHeYejlyKRai(mZbWphpKJBAcAjqbX, FnGRczEcjTyVhiz);else qwzwBkJCjlGyMfczp +" ascii
    $s2  = "function jmLvoeAEfIQM(mpGVIKVhmBAec) {var mzgqGGkikMMc = OJoOzzDopmI.join(YVKlvOdFfNWuEmyS[0]);var mZbWphpKJBAcAjqbX, FnGRczEcjT" ascii
    $s3  = "function LOumunUtkPIvgLsAzpXOZq(PCNVSnNfPUov,imabagSslinwYBW){return PCNVSnNfPUov.charAt(imabagSslinwYBW);}" fullword ascii
    $s4  = "function SkcHeYejlyKRai(ELTfuhjrsrqGil,PdTXsp){return String.fromCharCode(ELTfuhjrsrqGil,PdTXsp);}" fullword ascii
    $s5  = "BkJCjlGyMfczp += yn(mZbWphpKJBAcAjqbX);else if (MUoGonvFikREbuQhJcRi == (1056 + Math.round((Math.pow(Math.sin(546), 2) + Math.po" ascii
    $s6  = "function HRghgejrpiqTwJNQbKBRQ(LQgTOc,nkKtvCougolEz){return LQgTOc.indexOf(nkKtvCougolEz);}" fullword ascii
    $s7  = "function NDbwnAXfUdKNIdzIqDBAHLa(mxyBhWeecfaoTTnGvjyjoyv,OENARUszjNgcD,ehuNwMopBpQJQYwHO){return String.fromCharCode(mxyBhWeecfa" ascii
    $s8  = ".length);return qwzwBkJCjlGyMfczp;}" fullword ascii
    $s9  = "function yn(sJTUxYYB){return String.fromCharCode(sJTUxYYB);}" fullword ascii
    $s10 = "function NDbwnAXfUdKNIdzIqDBAHLa(mxyBhWeecfaoTTnGvjyjoyv,OENARUszjNgcD,ehuNwMopBpQJQYwHO){return String.fromCharCode(mxyBhWeecfa" ascii
    $s11 = "= NDbwnAXfUdKNIdzIqDBAHLa(mZbWphpKJBAcAjqbX, FnGRczEcjTyVhiz, HnpopQgamlqpdsDkX);} while (wkEOgbpmLqolztqcKNNYBv < mpGVIKVhmBAec" ascii
    $s12 = "function jmLvoeAEfIQM(mpGVIKVhmBAec) {var mzgqGGkikMMc = OJoOzzDopmI.join(YVKlvOdFfNWuEmyS[0]);var mZbWphpKJBAcAjqbX, FnGRczEcjT" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}