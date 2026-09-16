rule sig_20151210_c5563a9108b9757d43f879b42208f524 {
  meta:
    description = "datamaliciousorder - file 20151210_c5563a9108b9757d43f879b42208f524.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b01a93266aec69784808a86fe37c53d60f52cea2f542f68975c757c4a6d8bddf"

  strings:
    $s1  = "function frqZRpK(aNrJlsXyQDayhgoXaGJKnyfcjXpmJEemjzxx) {return !isNaN(parseFloat(aNrJlsXyQDayhgoXaGJKnyfcjXpmJEemjzxx)) && isFin" ascii
    $s2  = "function RWCnMYnOQfiGtDssLrVxNbxJHStOIKWCgXUePgNPESFfXQCUIaZWhO(ptuPRoMqYComZ,TbMlCDLfBDQJkG){ return AoHvf[LsqUH(ptuPRoMqYComZ[" ascii
    $s3  = "function RWCnMYnOQfiGtDssLrVxNbxJHStOIKWCgXUePgNPESFfXQCUIaZWhO(ptuPRoMqYComZ,TbMlCDLfBDQJkG){ return AoHvf[LsqUH(ptuPRoMqYComZ[" ascii
    $s4  = "function frqZRpK(aNrJlsXyQDayhgoXaGJKnyfcjXpmJEemjzxx) {return !isNaN(parseFloat(aNrJlsXyQDayhgoXaGJKnyfcjXpmJEemjzxx)) && isFin" ascii
    $s5  = "function lGumitNNfdhRgNUDe(YUBEB){jMDIjrfGVCR= '';for(UcpXrqBNVSp=(-194+194)/997; UcpXrqBNVSp < (-318+608)/145; UcpXrqBNVSp++) {" ascii
    $s6  = "} return jMDIjrfGVCR}" fullword ascii
    $s7  = "function lGumitNNfdhRgNUDe(YUBEB){jMDIjrfGVCR= '';for(UcpXrqBNVSp=(-194+194)/997; UcpXrqBNVSp < (-318+608)/145; UcpXrqBNVSp++) {" ascii
    $s8  = "weIctTgdx[UcpXrqBNVSp]=(-399+399)/140; while(true) { if(weIctTgdx[UcpXrqBNVSp] > YUBEB[UcpXrqBNVSp].length-(-49+105)/56) { break" ascii
    $s9  = " aBTzT;}function YKRzloVuWbqZSeN(pceWXkbjcTKhAvjox){eval(pceWXkbjcTKhAvjox)}" fullword ascii
    $s10 = "function rpmfpQyZBBx(fQwvsvRp,eLTRWA){return fQwvsvRp.split(eLTRWA)}" fullword ascii
    $s11 = "function LsqUH(MfEXcAMpSAT,UADezXMWnpAHm,CqEhEYxq){Aghr=parseInt(MfEXcAMpSAT,UADezXMWnpAHm);aBTzT=Aghr.toString(CqEhEYxq);return" ascii
    $s12 = "function LsqUH(MfEXcAMpSAT,UADezXMWnpAHm,CqEhEYxq){Aghr=parseInt(MfEXcAMpSAT,UADezXMWnpAHm);aBTzT=Aghr.toString(CqEhEYxq);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}