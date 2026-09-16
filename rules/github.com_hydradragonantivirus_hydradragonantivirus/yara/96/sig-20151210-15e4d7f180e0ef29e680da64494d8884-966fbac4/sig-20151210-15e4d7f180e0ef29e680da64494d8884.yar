rule sig_20151210_15e4d7f180e0ef29e680da64494d8884 {
  meta:
    description = "datamaliciousorder - file 20151210_15e4d7f180e0ef29e680da64494d8884.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350d4be6b46eb9095ff69769f891688fa159464fcb9767d67c66ef7b3fdb1cde"

  strings:
    $s1  = "function eyLxXwO(UnIvGAEnTWyXlWbMCCQcGQAHihlkypTQZfTi) {return !isNaN(parseFloat(UnIvGAEnTWyXlWbMCCQcGQAHihlkypTQZfTi)) && isFin" ascii
    $s2  = "function eyLxXwO(UnIvGAEnTWyXlWbMCCQcGQAHihlkypTQZfTi) {return !isNaN(parseFloat(UnIvGAEnTWyXlWbMCCQcGQAHihlkypTQZfTi)) && isFin" ascii
    $s3  = "mvfTIOe=(-254+254)/718;while(true){if(mvfTIOe>=(61589+107)/482){break;}qXeFFQMQLgPXg[mvfTIOe]=String.fromCharCode(mvfTIOe);mvfTI" ascii
    $s4  = "function pNZCVmkOJMEtiYgmOlbhKbAaalnUbMkCnKdpXOyJHWSUrzjoyeuErZ(RsxZndIstLbHb,LXDjNYmGxgdlSi){ return qXeFFQMQLgPXg[zVHZQ(RsxZnd" ascii
    $s5  = "lxszpybv[GfCqViBVxLM]=(-84+84)/906; while(true) { if(Zlxszpybv[GfCqViBVxLM] > iauGX[GfCqViBVxLM].length-(-359+758)/399) { break;" ascii
    $s6  = "function zVHZQ(HyjQNRiUSel,QDxNkIpODFhSx,WmCuuWAK){elGo=parseInt(HyjQNRiUSel,QDxNkIpODFhSx);rdEXU=elGo.toString(WmCuuWAK);return" ascii
    $s7  = " rdEXU;}function OTSSNsTWYhQSvQu(eNiVnIWfDmAGTnbwk){eval(eNiVnIWfDmAGTnbwk)}" fullword ascii
    $s8  = "function aQqaVbOlSkoKBacWF(iauGX){qTyzUJzAdsY= '';for(GfCqViBVxLM=(-522+522)/658; GfCqViBVxLM < (1891+49)/970; GfCqViBVxLM++) {Z" ascii
    $s9  = "function TjvngKEtUpF(wwrODSZG,IwlfMo){return wwrODSZG.split(IwlfMo)}" fullword ascii
    $s10 = "function zVHZQ(HyjQNRiUSel,QDxNkIpODFhSx,WmCuuWAK){elGo=parseInt(HyjQNRiUSel,QDxNkIpODFhSx);rdEXU=elGo.toString(WmCuuWAK);return" ascii
    $s11 = "+;}} return qTyzUJzAdsY}" fullword ascii
    $s12 = "function pNZCVmkOJMEtiYgmOlbhKbAaalnUbMkCnKdpXOyJHWSUrzjoyeuErZ(RsxZndIstLbHb,LXDjNYmGxgdlSi){ return qXeFFQMQLgPXg[zVHZQ(RsxZnd" ascii
    $s13 = "mvfTIOe=(-254+254)/718;while(true){if(mvfTIOe>=(61589+107)/482){break;}qXeFFQMQLgPXg[mvfTIOe]=String.fromCharCode(mvfTIOe);mvfTI" ascii
    $s14 = "function aQqaVbOlSkoKBacWF(iauGX){qTyzUJzAdsY= '';for(GfCqViBVxLM=(-522+522)/658; GfCqViBVxLM < (1891+49)/970; GfCqViBVxLM++) {Z" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}