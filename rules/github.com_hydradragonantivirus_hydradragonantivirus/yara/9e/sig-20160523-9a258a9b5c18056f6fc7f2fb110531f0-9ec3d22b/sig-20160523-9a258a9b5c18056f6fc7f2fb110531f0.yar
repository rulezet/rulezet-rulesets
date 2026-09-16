rule sig_20160523_9a258a9b5c18056f6fc7f2fb110531f0 {
  meta:
    description = "datamaliciousorder - file 20160523_9a258a9b5c18056f6fc7f2fb110531f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1867c870d81367fde739ef9ba30b90dc88f48ecbb71483797b32831eb0526f4c"

  strings:
    $s1  = "function JnhWBoSV(OfQRr) {var KPTxiufT=ijuWxbOmSEVwGgth[13];for(var XwSLc=0;XwSLc<OfQRr;XwSLc++){LftKN+=KPTxiufT.charAt(Math.flo" ascii
    $s2  = "function IVFKQPTldA() {return/*bbxUVUBHnPTCpEgRIfcPUQmjZBOWUJInLgwZzUngaFDpckixhKUifEPTUzcNORrnnbabXfVsRZWRYLrrczRceZDFHXRcwkOMj" ascii
    $s3  = "function gKXRYyoCmp(mdcpMIhK,ixTfkhrlCfLJ) {mdcpMIhK.Run(ixTfkhrlCfLJ, 0x1, 0x0);}" fullword ascii
    $s4  = "function JnhWBoSV(OfQRr) {var KPTxiufT=ijuWxbOmSEVwGgth[13];for(var XwSLc=0;XwSLc<OfQRr;XwSLc++){LftKN+=KPTxiufT.charAt(Math.flo" ascii
    $s5  = "function RSDY(wMdARcU,XoKSAGh) {wMdARcU.saveToFile(XoKSAGh, 2);}" fullword ascii
    $s6  = "function AwdoOeL(DWbU,mNdkV) {DWbU.write(mNdkV);}" fullword ascii
    $s7  = "function htWXT(JwjeZzJJ,CVXUS,UIBKmAswAK){IjAI(JwjeZzJJ);PejqxHdQ(JwjeZzJJ);AwdoOeL(JwjeZzJJ,CVXUS);ljNEfZdmw(JwjeZzJJ);RSDY(Jwj" ascii
    $s8  = "function PejqxHdQ(OMwTKSKcD) {OMwTKSKcD.type=1;}" fullword ascii
    $s9  = "function gyBG(jsIWWQ,xoeDAcq){lQqR = ijuWxbOmSEVwGgth[10].split(ijuWxbOmSEVwGgth[11]);xoeDAcq.open(lQqR[0]+lQqR[2]+lQqR[3], jsIW" ascii
    $s10 = "function FLwhj(WdZGRpOI,CczNtj,KZRYzjSrz){xNDhV=WdZGRpOI.split(KZRYzjSrz);ViSIILF = ijuWxbOmSEVwGgth[12];for(rjfLPnar=0;rjfLPnar" ascii
    $s11 = "function REDcvZEnZGEMD() {IVFKQPTldA().Sleep(2388008-264);}" fullword ascii
    $s12 = "function gyBG(jsIWWQ,xoeDAcq){lQqR = ijuWxbOmSEVwGgth[10].split(ijuWxbOmSEVwGgth[11]);xoeDAcq.open(lQqR[0]+lQqR[2]+lQqR[3], jsIW" ascii
    $s13 = "function nCvlcI(PwQFAu){return PwQFAu.ExpandEnvironmentStrings(ijuWxbOmSEVwGgth[9])}" fullword ascii
    $s14 = "function htWXT(JwjeZzJJ,CVXUS,UIBKmAswAK){IjAI(JwjeZzJJ);PejqxHdQ(JwjeZzJJ);AwdoOeL(JwjeZzJJ,CVXUS);ljNEfZdmw(JwjeZzJJ);RSDY(Jwj" ascii
    $s15 = "WQ, false);xoeDAcq.send();}" fullword ascii
    $s16 = "function ljNEfZdmw(tcBjYg) {var uRNTnSOTDk=[];tcBjYg.position=uRNTnSOTDk.length*(1643815-450);}" fullword ascii
    $s17 = "function tvonvUD(){return Math.random();}" fullword ascii
    $s18 = "function IjAI(ZpJzhR) {ZpJzhR.open();}" fullword ascii
    $s19 = "<CczNtj.length;rjfLPnar++) {ViSIILF+=xNDhV[CczNtj[rjfLPnar]];}return ViSIILF.substring(3,ViSIILF.length);}" fullword ascii
    $s20 = "if(tfnL>tJkeb.length) break;" fullword ascii

  condition:
    uint16(0) == 0x0827 and
    8 of them
}