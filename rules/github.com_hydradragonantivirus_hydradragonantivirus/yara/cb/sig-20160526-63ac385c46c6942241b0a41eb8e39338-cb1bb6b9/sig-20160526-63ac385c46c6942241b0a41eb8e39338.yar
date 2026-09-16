rule sig_20160526_63ac385c46c6942241b0a41eb8e39338 {
  meta:
    description = "datamaliciousorder - file 20160526_63ac385c46c6942241b0a41eb8e39338.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f5f01cf8d536ac57b172161dcdc00eb2d3549632524f6bf11530674b4c0576"

  strings:
    $s1  = "th.pow(Math.sin(281), 2) + Math.pow(Math.cos(281), 2) - 1))-276)) VcsZKFMsgEeEQiLl += Bw(gIHBhNNOUWEs);else if (ysxypH == (701 +" ascii
    $s2  = "function LKjwGOm(srGbSbcaHBwCf) {var FnhgubYAYJPrz = nJaOm.join(epDahp[0]);var gIHBhNNOUWEs, edPGFfYWoHhrV, OffvExBoNS, EmmhC, D" ascii
    $s3  = "function RfkPcZvv(jfeTZvlFLiVONsUpPiMTIKO,RwmiVDtJYYlnhJFbWcpCn){return jfeTZvlFLiVONsUpPiMTIKO.charAt(RwmiVDtJYYlnhJFbWcpCn);}" fullword ascii
    $s4  = ");return VcsZKFMsgEeEQiLl;}" fullword ascii
    $s5  = "function Bw(qByTEJUElaIGAG){return String.fromCharCode(qByTEJUElaIGAG);}" fullword ascii
    $s6  = "function ysfZvlLKUN(KqROlFgiOo,ZYMyEcPvwb){return String.fromCharCode(KqROlFgiOo,ZYMyEcPvwb);}" fullword ascii
    $s7  = "function muJuSsy(JItVatrLUCyu,lojFQitItOqaPe){return JItVatrLUCyu.indexOf(lojFQitItOqaPe);}" fullword ascii
    $s8  = "function QcWjNuPHNY(RRZRsFb,HLvLisBQYqalLEPAKPezVkik,HZNxFPQbnRSdvxHvql){return String.fromCharCode(RRZRsFb,HLvLisBQYqalLEPAKPez" ascii
    $s9  = "function QcWjNuPHNY(RRZRsFb,HLvLisBQYqalLEPAKPezVkik,HZNxFPQbnRSdvxHvql){return String.fromCharCode(RRZRsFb,HLvLisBQYqalLEPAKPez" ascii
    $s10 = "PGFfYWoHhrV);else VcsZKFMsgEeEQiLl += QcWjNuPHNY(gIHBhNNOUWEs, edPGFfYWoHhrV, OffvExBoNS);} while (LQvbAi < srGbSbcaHBwCf.length" ascii
    $s11 = "function LKjwGOm(srGbSbcaHBwCf) {var FnhgubYAYJPrz = nJaOm.join(epDahp[0]);var gIHBhNNOUWEs, edPGFfYWoHhrV, OffvExBoNS, EmmhC, D" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}