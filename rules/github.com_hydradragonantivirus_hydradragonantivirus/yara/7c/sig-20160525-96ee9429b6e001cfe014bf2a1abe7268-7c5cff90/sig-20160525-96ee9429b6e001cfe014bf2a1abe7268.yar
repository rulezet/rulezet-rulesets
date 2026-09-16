rule sig_20160525_96ee9429b6e001cfe014bf2a1abe7268 {
  meta:
    description = "datamaliciousorder - file 20160525_96ee9429b6e001cfe014bf2a1abe7268.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dfe85da23c73af4acaafae3d3db779d0da18edbff0ce0f6dedb3c09c9f86a31"

  strings:
    $s1  = "function jvRWMv(SoDYyWJBBpFNm) {var hyNQbD = bjVDBFNEkYUxWKNIjLI.join(fEgjUWokcmbrHb[0]);var pVZunS, digkZWYWCEAPBwypPRiLA, qUUu" ascii
    $s2  = "5), 2) - 1))-954)) ibYuivysKGJLFVBW += prDfeNiFts(pVZunS, digkZWYWCEAPBwypPRiLA);else ibYuivysKGJLFVBW += RirhWWZTfUKBA(pVZunS, " ascii
    $s3  = "KGJLFVBW += sx(pVZunS);else if (gcxCpnkEGomxfzhTfZGRKLv == (1018 + Math.round((Math.pow(Math.sin(675), 2) + Math.pow(Math.cos(67" ascii
    $s4  = "function FTjNMsadliDv(thuBAvgxkdPbX,SWhpCkxTpwalRvLCZ){return thuBAvgxkdPbX.charAt(SWhpCkxTpwalRvLCZ);}" fullword ascii
    $s5  = "function prDfeNiFts(OTgaFoeawGhoCSyAjKKFu,ktoRIQDB){return String.fromCharCode(OTgaFoeawGhoCSyAjKKFu,ktoRIQDB);}" fullword ascii
    $s6  = "function jvRWMv(SoDYyWJBBpFNm) {var hyNQbD = bjVDBFNEkYUxWKNIjLI.join(fEgjUWokcmbrHb[0]);var pVZunS, digkZWYWCEAPBwypPRiLA, qUUu" ascii
    $s7  = "function sx(qEjQC){return String.fromCharCode(qEjQC);}" fullword ascii
    $s8  = "function VjOBevO(QFMmIYJLfrNTugwbyv,dcPVqEiTjFVKlrTRlYlAgIDi){return QFMmIYJLfrNTugwbyv.indexOf(dcPVqEiTjFVKlrTRlYlAgIDi);}" fullword ascii
    $s9  = "digkZWYWCEAPBwypPRiLA, qUUuJMKNprXBKUVrgRTu);} while (yjKhljcHTHBtAtV < SoDYyWJBBpFNm.length);return ibYuivysKGJLFVBW;}" fullword ascii
    $s10 = "function RirhWWZTfUKBA(XqtMF,sjaMVAif,HuDOb){return String.fromCharCode(XqtMF,sjaMVAif,HuDOb);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}