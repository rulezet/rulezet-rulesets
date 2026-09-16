rule sig_20151217_379e4896416fd39b6fdb81c7ed5cdb8c {
  meta:
    description = "datamaliciousorder - file 20151217_379e4896416fd39b6fdb81c7ed5cdb8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "696ddf416d8421c86e2be600a6cb033c9de798b9aab43ed3ef84ab7101575d06"

  strings:
    $s1  = "th.cos(342), 2) - 1)));} FyPblauLh[cWMgXFCmUQs]++;}cWMgXFCmUQs++;} return kvWUhOnXdph}" fullword ascii
    $s2  = "h.pow(Math.cos(764), 2) - 1)); while(true) { if(FyPblauLh[cWMgXFCmUQs] > zIQGp[cWMgXFCmUQs].length-(59+915)/974) { break; } if (" ascii
    $s3  = ") - 1));while(true){if (cWMgXFCmUQs >= (5669+43)/952){break;}FyPblauLh[cWMgXFCmUQs]=Math.round((Math.pow(Math.sin(764), 2) + Mat" ascii
    $s4  = "function SEBvlmNTAmZWDJQtC(zIQGp){kvWUhOnXdph= '';cWMgXFCmUQs=Math.round((Math.pow(Math.sin(579), 2) + Math.pow(Math.cos(579), 2" ascii
    $s5  = "function SEBvlmNTAmZWDJQtC(zIQGp){kvWUhOnXdph= '';cWMgXFCmUQs=Math.round((Math.pow(Math.sin(579), 2) + Math.pow(Math.cos(579), 2" ascii
    $s6  = "function ErkoIqd(OJYCGBQFHeHbKCMzucjQaJKgmuzoUytpMmDx) {return !hcWaDLwoAiG(inLptZCOiShJPRA(OJYCGBQFHeHbKCMzucjQaJKgmuzoUytpMmDx" ascii
    $s7  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s8  = "function ErkoIqd(OJYCGBQFHeHbKCMzucjQaJKgmuzoUytpMmDx) {return !hcWaDLwoAiG(inLptZCOiShJPRA(OJYCGBQFHeHbKCMzucjQaJKgmuzoUytpMmDx" ascii
    $s9  = "function ABSzCtLPUGhn(seNYpZwjOowFn) {return isFinite(seNYpZwjOowFn);}" fullword ascii
    $s10 = "function B(TNKcKbDpGOJt,PQhRumuHbywpwy){TNKcKbDpGOJt.push(PQhRumuHbywpwy);}" fullword ascii
    $s11 = "function rddAPRxMJzfVBpCsW(JPrYlRCPIW,GUeoQkxmdu) {return parseInt(JPrYlRCPIW,GUeoQkxmdu);}" fullword ascii
    $s12 = "function YhXPtLvsRfGeGLZWPieJUURNIypsJwDmFePGqYuUEiBFTBNwJTrFQN(aHcvOEpSHIZPS,TWniMRrvThGsOt){ return BeJzXzG[IUnJTwaX[nfmHv(aHc" ascii
    $s13 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s14 = "K);return eWpnP;}" fullword ascii
    $s15 = "function hcWaDLwoAiG(IUpWUZLxHWXteT) {return isNaN(IUpWUZLxHWXteT);}" fullword ascii
    $s16 = ",'V','_','3','y',':','o','P',']','W','0','U',';','Q','X','T','&','f','+','Y','M','Z','w','O','(','m','G','H','[','@','u',String." ascii
    $s17 = "function nfmHv(sGRIRoGSNGE,qkFcTYYgotCmO,EWcTefrK){udID=rddAPRxMJzfVBpCsW(sGRIRoGSNGE,qkFcTYYgotCmO);eWpnP=udID.toString(EWcTefr" ascii
    $s18 = "function YhXPtLvsRfGeGLZWPieJUURNIypsJwDmFePGqYuUEiBFTBNwJTrFQN(aHcvOEpSHIZPS,TWniMRrvThGsOt){ return BeJzXzG[IUnJTwaX[nfmHv(aHc" ascii
    $s19 = "function nfmHv(sGRIRoGSNGE,qkFcTYYgotCmO,EWcTefrK){udID=rddAPRxMJzfVBpCsW(sGRIRoGSNGE,qkFcTYYgotCmO);eWpnP=udID.toString(EWcTefr" ascii
    $s20 = "function c(tUTpAdhdMbTlLX,nGWMhKmxZMhep,RMgFgzzoQgL) {tUTpAdhdMbTlLX[nGWMhKmxZMhep]=RMgFgzzoQgL;}" fullword ascii

  condition:
    uint16(0) == 0x5549 and
    8 of them
}