rule sig_20160526_3085251605fc472fcd4d282bba506112 {
  meta:
    description = "datamaliciousorder - file 20160526_3085251605fc472fcd4d282bba506112.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c46e9da71824b948b015d6b48399ad0698df3945a189a0a061581f6e178922"

  strings:
    $s1  = "ow(Math.cos(713), 2) - 1))-412)) ptxFcudpaXKUWPvFNtPU += HVuNEivlJNf(HMhWTYrGuibiTwfTLFQS, ECrCPKCywjEjwT);else ptxFcudpaXKUWPvF" ascii
    $s2  = "93)) ptxFcudpaXKUWPvFNtPU += oY(HMhWTYrGuibiTwfTLFQS);else if (avdqUjR == (476 + Math.round((Math.pow(Math.sin(713), 2) + Math.p" ascii
    $s3  = "function HkJpIFcJgSMIT(JjbrXBNNoLjUG) {var aWLaBEMTPwzBdBqXRVInT = SsXxFblR.join(NqCcVgZnkO[0]);var HMhWTYrGuibiTwfTLFQS, ECrCPK" ascii
    $s4  = "function CegvHMiHJvPqYFJixNvOSqW(HMBxSjFZFAAJoyHMeBJtNXI,Fktxdbx){return HMBxSjFZFAAJoyHMeBJtNXI.charAt(Fktxdbx);}" fullword ascii
    $s5  = "function yHnOxppwaXaqLd(QMzxV,XuqYsSsIdqxNZAuYz){return QMzxV.indexOf(XuqYsSsIdqxNZAuYz);}" fullword ascii
    $s6  = "function HkJpIFcJgSMIT(JjbrXBNNoLjUG) {var aWLaBEMTPwzBdBqXRVInT = SsXxFblR.join(NqCcVgZnkO[0]);var HMhWTYrGuibiTwfTLFQS, ECrCPK" ascii
    $s7  = "function oY(XTBsxhRuGPCywkNSJWu){return String.fromCharCode(XTBsxhRuGPCywkNSJWu);}" fullword ascii
    $s8  = "function tZYVlgvlCyPgLXX(rorVnm,akGKOhioTFcNPTDwObm,MYShcOVwsVuaBGUqllz){return String.fromCharCode(rorVnm,akGKOhioTFcNPTDwObm,M" ascii
    $s9  = "function tZYVlgvlCyPgLXX(rorVnm,akGKOhioTFcNPTDwObm,MYShcOVwsVuaBGUqllz){return String.fromCharCode(rorVnm,akGKOhioTFcNPTDwObm,M" ascii
    $s10 = "function HVuNEivlJNf(JWNTMUzdFxznannhoUAFpRt,pXKqIcwNOrQRzkBVVxfNrs){return String.fromCharCode(JWNTMUzdFxznannhoUAFpRt,pXKqIcwN" ascii
    $s11 = "function HVuNEivlJNf(JWNTMUzdFxznannhoUAFpRt,pXKqIcwNOrQRzkBVVxfNrs){return String.fromCharCode(JWNTMUzdFxznannhoUAFpRt,pXKqIcwN" ascii
    $s12 = "NtPU += tZYVlgvlCyPgLXX(HMhWTYrGuibiTwfTLFQS, ECrCPKCywjEjwT, rkvLWHCajxvhEkXjpJgaE);} while (Klipf < JjbrXBNNoLjUG.length);retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}