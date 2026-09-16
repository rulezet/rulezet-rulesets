rule sig_20160526_79eac9e15567a4ca35451e0b5663eac0 {
  meta:
    description = "datamaliciousorder - file 20160526_79eac9e15567a4ca35451e0b5663eac0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d45be30e9a065c09e157ffb3464693db56f2c2ccc1e5b52e8f0abfe5f5c406d"

  strings:
    $s1  = "function MxmaWXOvtaKM(JrLtMVRdGRbqu) {var laJRhFpYc = AqnZsBw.join(iHJfDFAIuac[0]);var mHEHGJTmJuH, xNHRngWXTxFr, zjZDCXJZCczGzr" ascii
    $s2  = "5), 2) - 1))-911) & 0xff;zjZDCXJZCczGzrNnt = gvABrnAVbDxOUMs & 0xff;if (toeqsRRSZWiLahHQtWo == (332 + Math.round((Math.pow(Math." ascii
    $s3  = "sin(717), 2) + Math.pow(Math.cos(717), 2) - 1))-268)) odUrOPYyONSNbeJbaEIXfQ += cD(mHEHGJTmJuH);else if (KBEsKLGpTj == (744 + Ma" ascii
    $s4  = "function CxfHmegdyNhZHvtylwLj(sMZDYWaeWAOJvw,dGvYxbFziULjuqNAZFmXCkpD){return sMZDYWaeWAOJvw.charAt(dGvYxbFziULjuqNAZFmXCkpD);}" fullword ascii
    $s5  = "function cD(ZJGOTXPsR){return String.fromCharCode(ZJGOTXPsR);}" fullword ascii
    $s6  = "function fQcZPfeTNhpVtwhhSxwJu(LztZuMNYhNbZUkFSsoER,KEBYDiaFJxytIlAY){return String.fromCharCode(LztZuMNYhNbZUkFSsoER,KEBYDiaFJx" ascii
    $s7  = "function mpRyIXrWoxdXePetnro(FhAZlBDyiuNRfswEGeHc,DgxBr){return FhAZlBDyiuNRfswEGeHc.indexOf(DgxBr);}" fullword ascii
    $s8  = "function fQcZPfeTNhpVtwhhSxwJu(LztZuMNYhNbZUkFSsoER,KEBYDiaFJxytIlAY){return String.fromCharCode(LztZuMNYhNbZUkFSsoER,KEBYDiaFJx" ascii
    $s9  = "function MxmaWXOvtaKM(JrLtMVRdGRbqu) {var laJRhFpYc = AqnZsBw.join(iHJfDFAIuac[0]);var mHEHGJTmJuH, xNHRngWXTxFr, zjZDCXJZCczGzr" ascii
    $s10 = "function rPxlrfuUxYCKTGtdV(PsBrIAh,WPNbt,cGdoedxkICjqJfTS){return String.fromCharCode(PsBrIAh,WPNbt,cGdoedxkICjqJfTS);}" fullword ascii
    $s11 = "EHGJTmJuH, xNHRngWXTxFr);else odUrOPYyONSNbeJbaEIXfQ += rPxlrfuUxYCKTGtdV(mHEHGJTmJuH, xNHRngWXTxFr, zjZDCXJZCczGzrNnt);} while " ascii
    $s12 = "(plBAvHKGnTjNhLOcRB < JrLtMVRdGRbqu.length);return odUrOPYyONSNbeJbaEIXfQ;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}