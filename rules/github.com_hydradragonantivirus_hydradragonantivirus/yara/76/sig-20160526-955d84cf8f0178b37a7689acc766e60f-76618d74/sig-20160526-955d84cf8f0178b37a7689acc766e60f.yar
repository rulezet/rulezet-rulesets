rule sig_20160526_955d84cf8f0178b37a7689acc766e60f {
  meta:
    description = "datamaliciousorder - file 20160526_955d84cf8f0178b37a7689acc766e60f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f8b23af5a8541c2694266edead4f8a4f9e248a95d8c77e94af3ac9135b555a5"

  strings:
    $s1  = " Math.pow(Math.cos(513), 2) - 1))-213)) YrXPRxmjPUE += dx(GEfTXlpVVroiRmv);else if (ETwErWoSMBMFs == (575 + Math.round((Math.pow" ascii
    $s2  = "function kZeBuDaXLwdQxR(fbapmhPopHwfb) {var nKiDrSbZ = RIFJSrNrt.join(CXZVyklRBlYjf[0]);var GEfTXlpVVroiRmv, TRvbYTejMkUkuE, RgU" ascii
    $s3  = "opHwfb,fWdhtdDYvhZIsKW++));oHfCTHZsbxSKHRYAHVkCP = ypDUFDLxDCSG<< (950 + Math.round((Math.pow(Math.sin(745), 2) + Math.pow(Math." ascii
    $s4  = "function kwPdTAoKXKJldEGvytWqr(DXfcWsvHAHJ,zKxChToqwQDbaEa){return DXfcWsvHAHJ.charAt(zKxChToqwQDbaEa);}" fullword ascii
    $s5  = "hPopHwfb.length);return YrXPRxmjPUE;}" fullword ascii
    $s6  = "function dx(tCpZs){return String.fromCharCode(tCpZs);}" fullword ascii
    $s7  = "function JquaqgGrBlRuBOFJdgJ(dehMDGNTpFpAGOjQofAuE,byvACjhKwRiLFsUxGDUQ){return String.fromCharCode(dehMDGNTpFpAGOjQofAuE,byvACj" ascii
    $s8  = "function aOkUpoMWGpG(IyAiJJextBLIQw,sGATt){return IyAiJJextBLIQw.indexOf(sGATt);}" fullword ascii
    $s9  = "function kZeBuDaXLwdQxR(fbapmhPopHwfb) {var nKiDrSbZ = RIFJSrNrt.join(CXZVyklRBlYjf[0]);var GEfTXlpVVroiRmv, TRvbYTejMkUkuE, RgU" ascii
    $s10 = "function LrYPImTwAAKOrGEzdmcId(VLMMT,eajZeYFJFINKRfRRBor,KYdaRC){return String.fromCharCode(VLMMT,eajZeYFJFINKRfRRBor,KYdaRC);}" fullword ascii
    $s11 = "function JquaqgGrBlRuBOFJdgJ(dehMDGNTpFpAGOjQofAuE,byvACjhKwRiLFsUxGDUQ){return String.fromCharCode(dehMDGNTpFpAGOjQofAuE,byvACj" ascii
    $s12 = "else YrXPRxmjPUE += LrYPImTwAAKOrGEzdmcId(GEfTXlpVVroiRmv, TRvbYTejMkUkuE, RgUascshcdRZVbhCMsP);} while (fWdhtdDYvhZIsKW < fbapm" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}