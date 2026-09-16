rule sig_20160527_fa23f74031799da13b1857ad4969c4bc {
  meta:
    description = "datamaliciousorder - file 20160527_fa23f74031799da13b1857ad4969c4bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0bf7d8e0188d97ea448a452999b7aa07c30c97c828d2ad74b92f5e565393767"

  strings:
    $s1  = "function UGcKFPAPB() {return WScript;}function CqgHdkFRd(){return NvEyVh.ExpandEnvironmentStrings(suScqic())}" fullword ascii
    $s2  = "function YVwoKEwDH(KYJhDIKAQmLwvButqANo,pbmRUpdXnJpPgolNs){return KYJhDIKAQmLwvButqANo.charAt(pbmRUpdXnJpPgolNs);}" fullword ascii
    $s3  = "function wK(AKeYGtiof){return String.fromCharCode(AKeYGtiof);}" fullword ascii
    $s4  = "ring.fromCharCode(92)+QYaLOmxhNJobiTtZbrbOYhq[4],true);" fullword ascii
    $s5  = "function WldisJ(FiXBBwAHJiOpx,aOKiJ) {var TJnsi=[QYaLOmxhNJobiTtZbrbOYhq[15]];FiXBBwAHJiOpx[TJnsi[0]](aOKiJ,0x1,0x0)}" fullword ascii
    $s6  = "function dtFgj(){return GdsEwPYJs(QYaLOmxhNJobiTtZbrbOYhq[12],[0,3,6],QYaLOmxhNJobiTtZbrbOYhq[13]);}" fullword ascii
    $s7  = "function GdsEwPYJs(qHBMTB,FhgoSZg,rcSJthkbRdW){LhXtgpuZSjQtr=qHBMTB.split(rcSJthkbRdW);oGvrkhQsDXa = QYaLOmxhNJobiTtZbrbOYhq[14]" ascii
    $s8  = "var AIlMDtXOAc=function(){return new ActiveXObject(QYaLOmxhNJobiTtZbrbOYhq[0]);}();" fullword ascii
    $s9  = "function avtnswNlBHrNxJZqiK(MxLyvYfBzUy,JjKjYgaUouIOhJbSrrnhPMeg,tGbKv){return String.fromCharCode(MxLyvYfBzUy,JjKjYgaUouIOhJbSr" ascii
    $s10 = "function GdsEwPYJs(qHBMTB,FhgoSZg,rcSJthkbRdW){LhXtgpuZSjQtr=qHBMTB.split(rcSJthkbRdW);oGvrkhQsDXa = QYaLOmxhNJobiTtZbrbOYhq[14]" ascii
    $s11 = "var pZPkzG = AIlMDtXOAc.createtextfile(NvEyVh.ExpandEnvironmentStrings(QYaLOmxhNJobiTtZbrbOYhq[2]+QYaLOmxhNJobiTtZbrbOYhq[3])+St" ascii
    $s12 = "function iItEnedlrAEmRHRScugDw(UFjnOJEut,IDbdxoVkSexldNgm){return UFjnOJEut.indexOf(IDbdxoVkSexldNgm);}" fullword ascii
    $s13 = "function ECXJKWRDEYVbGF(){return GdsEwPYJs(QYaLOmxhNJobiTtZbrbOYhq[10],[2,4,8,10],QYaLOmxhNJobiTtZbrbOYhq[11]);}" fullword ascii
    $s14 = "function eNSJPyS(kTaJYDhRAtei,HWKXAevdWseUOnzxjzwtqIis){return String.fromCharCode(kTaJYDhRAtei,HWKXAevdWseUOnzxjzwtqIis);}" fullword ascii
    $s15 = "bnEb);else if (irJYfIiUYi == 64) ovnUZLR += eNSJPyS(dYVSpTHQbnEb, skiegRv);else ovnUZLR += avtnswNlBHrNxJZqiK(dYVSpTHQbnEb, skie" ascii
    $s16 = "function xXHIhdLEJpCC(SrJzyxVbsBtWN) {var KrvFzSPle = nhhcpdgFhxjvGKWOoIw.join(QYaLOmxhNJobiTtZbrbOYhq[6]);var dYVSpTHQbnEb, ski" ascii
    $s17 = "gRv, WHDNUlJWwUPUSOXJ);} while (AGqnzjihxKn < SrJzyxVbsBtWN.length);return ovnUZLR;}" fullword ascii
    $s18 = "function suScqic(){return GdsEwPYJs(QYaLOmxhNJobiTtZbrbOYhq[8],[1,5,7],QYaLOmxhNJobiTtZbrbOYhq[9]);}" fullword ascii
    $s19 = "var NvEyVh=function(){return UGcKFPAPB().CreateObject(QYaLOmxhNJobiTtZbrbOYhq[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function xXHIhdLEJpCC(SrJzyxVbsBtWN) {var KrvFzSPle = nhhcpdgFhxjvGKWOoIw.join(QYaLOmxhNJobiTtZbrbOYhq[6]);var dYVSpTHQbnEb, ski" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}