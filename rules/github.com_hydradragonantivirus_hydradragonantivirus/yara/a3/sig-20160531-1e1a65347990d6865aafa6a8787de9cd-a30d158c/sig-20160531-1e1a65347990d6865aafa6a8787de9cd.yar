rule sig_20160531_1e1a65347990d6865aafa6a8787de9cd {
  meta:
    description = "datamaliciousorder - file 20160531_1e1a65347990d6865aafa6a8787de9cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "366f8c0f00b625030d8865263c20e9ef7760b931beb99d1f77b0dcaf46abc7f7"

  strings:
    $s1  = "var XGBSqjJRGKI=function(){return WScript.CreateObject(owNYmKjtECojVEgnIfudq[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function nQOGA(KUrXB,DtDANqVMALKM){return KUrXB.charAt(DtDANqVMALKM);}" fullword ascii
    $s3  = "function nJyOAMwbl(){return XGBSqjJRGKI.ExpandEnvironmentStrings(ManFotfhUZ())}" fullword ascii
    $s4  = "function ZaQmeeOSrK(){return AGfBZXPHvizRaN(owNYmKjtECojVEgnIfudq[11],[2,4,8,10],owNYmKjtECojVEgnIfudq[12]);}" fullword ascii
    $s5  = "function BoYxdrLon(tVRNZUn,dcOlPvfw) {var jRbWiCSQ=[owNYmKjtECojVEgnIfudq[15]];tVRNZUn[jRbWiCSQ[0]]" fullword ascii
    $s6  = " 0xff;if (ZhuYJjvBzVOVoEFiWfovHyD == 64) MhBGVdOQMcZTz += Ss(TegXSbdzhmhJUyzhpQHZkKb);else if (fIbTHVYKbFoDzfYVRuboUdQ == 64) Mh" ascii
    $s7  = "(dcOlPvfw,0x1,0x0)}function rdnWGtPnZsub(joXiZtVk,KdOqlphcthiI,qSHcbzsrqSiC){var ZOomgsaT=joXiZtVk.createtextfile(KdOqlphcthiI,t" ascii
    $s8  = "function ZPmXjK(bZWVrXAjbOzLA) {var ORiHBCWWKQEzkCLDkZH = bbsekFvATGcGCXs.join(owNYmKjtECojVEgnIfudq[7]);var TegXSbdzhmhJUyzhpQH" ascii
    $s9  = "function AGfBZXPHvizRaN(QbLmFoF,SYljnVY,tcsqETdQcW){DHbEHeOU=QbLmFoF.split(tcsqETdQcW);nChcXERiiqeeJK = owNYmKjtECojVEgnIfudq[0]" ascii
    $s10 = "function zgopOKgrTahdM(IvgDEsAcsAuQZlrk,HEJNQJdTx){return IvgDEsAcsAuQZlrk.indexOf(HEJNQJdTx);}" fullword ascii
    $s11 = "function Ss(hNjaZvzaLsPsiEXAYrD){return String.fromCharCode(hNjaZvzaLsPsiEXAYrD);}" fullword ascii
    $s12 = ";for(mbNEOjuvNkFrFo=0;mbNEOjuvNkFrFo<SYljnVY.length;mbNEOjuvNkFrFo++) {nChcXERiiqeeJK+=DHbEHeOU[SYljnVY[mbNEOjuvNkFrFo]];}return" ascii
    $s13 = "function OtxzbzoTVBxVlRf(CetDWQXsZPMgGpcOzv,lmwMITB){return String.fromCharCode(CetDWQXsZPMgGpcOzv,lmwMITB);}" fullword ascii
    $s14 = "function ManFotfhUZ(){return AGfBZXPHvizRaN(owNYmKjtECojVEgnIfudq[9],[1,5,7],owNYmKjtECojVEgnIfudq[10]);}" fullword ascii
    $s15 = "function Wtcejo(yuRve,mFHBHphiFWXpuOwFkSZRGv,mghRjLpjwiLdQpCHzBcnbma){return String.fromCharCode(yuRve,mFHBHphiFWXpuOwFkSZRGv,mg" ascii
    $s16 = "function AGfBZXPHvizRaN(QbLmFoF,SYljnVY,tcsqETdQcW){DHbEHeOU=QbLmFoF.split(tcsqETdQcW);nChcXERiiqeeJK = owNYmKjtECojVEgnIfudq[0]" ascii
    $s17 = "(dcOlPvfw,0x1,0x0)}function rdnWGtPnZsub(joXiZtVk,KdOqlphcthiI,qSHcbzsrqSiC){var ZOomgsaT=joXiZtVk.createtextfile(KdOqlphcthiI,t" ascii
    $s18 = "BGVdOQMcZTz += OtxzbzoTVBxVlRf(TegXSbdzhmhJUyzhpQHZkKb, KIEgaqPUulEcxdypMDZKv);else MhBGVdOQMcZTz += Wtcejo(TegXSbdzhmhJUyzhpQHZ" ascii
    $s19 = "kKb, KIEgaqPUulEcxdypMDZKv, DrfVjppKXbSYNxykDTjpSZM);} while (SjXkUTifDOsuRzsAppMLy < bZWVrXAjbOzLA.length);return MhBGVdOQMcZTz" ascii
    $s20 = "function Wtcejo(yuRve,mFHBHphiFWXpuOwFkSZRGv,mghRjLpjwiLdQpCHzBcnbma){return String.fromCharCode(yuRve,mFHBHphiFWXpuOwFkSZRGv,mg" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}