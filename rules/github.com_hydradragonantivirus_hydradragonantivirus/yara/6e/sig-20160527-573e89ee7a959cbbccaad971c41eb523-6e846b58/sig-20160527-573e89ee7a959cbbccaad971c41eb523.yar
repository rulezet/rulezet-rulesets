rule sig_20160527_573e89ee7a959cbbccaad971c41eb523 {
  meta:
    description = "datamaliciousorder - file 20160527_573e89ee7a959cbbccaad971c41eb523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5650496b43c88cfa73c84d746268dcf007dfa82a80a2fc3d6c6ebc526100134b"

  strings:
    $s1  = "function OrzNNWKTxP() {return WScript;}function orZQFfuWDoMrD(){return NitoUHNSIau.ExpandEnvironmentStrings(VwPweU())}" fullword ascii
    $s2  = "function QgdXGJGsjdkoUuxoIRE(tAQlhDQR,VwLYFUZRsCeSZvWTI){return tAQlhDQR.charAt(VwLYFUZRsCeSZvWTI);}" fullword ascii
    $s3  = "var NitoUHNSIau=function(){return OrzNNWKTxP().CreateObject(QbqJA[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s4  = "function jKtaBWTzXcr(GjDetq,vJjVGISIf) {var LtzwVDe=[QbqJA[15]];GjDetq[LtzwVDe[0]](vJjVGISIf,0x1,0x0)}" fullword ascii
    $s5  = "function aTiAhhOWdJbzgVGlcyxvYqah(pdKGGZuUGsjANd,zwESfq,cZcHHqrbcEJByblzDYpm){return String.fromCharCode(pdKGGZuUGsjANd,zwESfq,c" ascii
    $s6  = "O=0;swocqBwaNZCSMO<sbvFnBasXZ.length;swocqBwaNZCSMO++) {mmPfglKNj+=NMlihOf[sbvFnBasXZ[swocqBwaNZCSMO]];}return mmPfglKNj.substri" ascii
    $s7  = "function rgrLLQUOgMqLpB(sLhXFUhtvGKLU,fdRgXyhtpd){return String.fromCharCode(sLhXFUhtvGKLU,fdRgXyhtpd);}" fullword ascii
    $s8  = "var EbMZFtJr=function(){return new ActiveXObject(QbqJA[0]);}();" fullword ascii
    $s9  = "function P(YZlxuN){return String.fromCharCode(YZlxuN);}" fullword ascii
    $s10 = "function TkeKdbAnozRU(pDQLko,sbvFnBasXZ,UDKvkbqQCVfL){NMlihOf=pDQLko.split(UDKvkbqQCVfL);mmPfglKNj = QbqJA[14];for(swocqBwaNZCSM" ascii
    $s11 = "var qhsmEYUUQYxT = EbMZFtJr.createtextfile(NitoUHNSIau.ExpandEnvironmentStrings(QbqJA[2]+QbqJA[3])+String.fromCharCode(92)+QbqJA" ascii
    $s12 = "function aTiAhhOWdJbzgVGlcyxvYqah(pdKGGZuUGsjANd,zwESfq,cZcHHqrbcEJByblzDYpm){return String.fromCharCode(pdKGGZuUGsjANd,zwESfq,c" ascii
    $s13 = "function vKLMo(LMjlyBbryfuVW) {var BSskPfpQLPTufjOV = JJzcfSmLuLWylYVodlbXWJD.join(QbqJA[6]);var dgWsChIrENdWILwTVT, CswUKgYBFrO" ascii
    $s14 = "function tBMiaHFCVh(){return TkeKdbAnozRU(QbqJA[10],[2,4,8,10],QbqJA[11]);}" fullword ascii
    $s15 = "function naVKcnrlurTA(){return TkeKdbAnozRU(QbqJA[12],[0,3,6],QbqJA[13]);}" fullword ascii
    $s16 = "function VwPweU(){return TkeKdbAnozRU(QbqJA[8],[1,5,7],QbqJA[9]);}" fullword ascii
    $s17 = "function xkZWU(ymDrZcZWnaGNVIOABYnOc,hhoKdYfbziHYBxjAhCriyc){return ymDrZcZWnaGNVIOABYnOc.indexOf(hhoKdYfbziHYBxjAhCriyc);}" fullword ascii
    $s18 = "function TkeKdbAnozRU(pDQLko,sbvFnBasXZ,UDKvkbqQCVfL){NMlihOf=pDQLko.split(UDKvkbqQCVfL);mmPfglKNj = QbqJA[14];for(swocqBwaNZCSM" ascii
    $s19 = "function vKLMo(LMjlyBbryfuVW) {var BSskPfpQLPTufjOV = JJzcfSmLuLWylYVodlbXWJD.join(QbqJA[6]);var dgWsChIrENdWILwTVT, CswUKgYBFrO" ascii
    $s20 = "[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}