rule sig_20160531_2f657a6a2bcc07e6612eb83ad0e1c43e {
  meta:
    description = "datamaliciousorder - file 20160531_2f657a6a2bcc07e6612eb83ad0e1c43e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c574c017a389812015cff04342bbcfe9c170eb29d1ccc1b86edd48bf9a3d0b50"

  strings:
    $s1  = "var dVxFaC=function(){return WScript.CreateObject(dEBWulvFpK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function whvNGL(LqhOpyViBrzwfMsRUv,VJPhbSrxK){return LqhOpyViBrzwfMsRUv.charAt(VJPhbSrxK);}" fullword ascii
    $s3  = "PjuH,true);VGFzyjsQWrLFjY.WriteLine(bRFYAqbU);VGFzyjsQWrLFjY.Close();}" fullword ascii
    $s4  = "function Nn(aiFDWkJxGZcKpQRwmq){return String.fromCharCode(aiFDWkJxGZcKpQRwmq);}" fullword ascii
    $s5  = "function mnvUQLBBdsWD(wHSGApEyIsyQAOBTG,LLtikKMv,qRYkWoN){return String.fromCharCode(wHSGApEyIsyQAOBTG,LLtikKMv,qRYkWoN);}" fullword ascii
    $s6  = "function LAcJYbuB(){return QvNJUjkP(dEBWulvFpK[9],[1,5,7],dEBWulvFpK[10]);}" fullword ascii
    $s7  = "function igSoiHW(YaLZDStsS,ACPmrEfikk){return YaLZDStsS.indexOf(ACPmrEfikk);}" fullword ascii
    $s8  = "(YezHNL,0x1,0x0)}function qLhPDwXQZgty(olyciJSfNHI,haDdBmmBPjuH,bRFYAqbU){var VGFzyjsQWrLFjY=olyciJSfNHI.createtextfile(haDdBmmB" ascii
    $s9  = "(YezHNL,0x1,0x0)}function qLhPDwXQZgty(olyciJSfNHI,haDdBmmBPjuH,bRFYAqbU){var VGFzyjsQWrLFjY=olyciJSfNHI.createtextfile(haDdBmmB" ascii
    $s10 = "function IwuKnsNNTx(DaDWmvZx,YezHNL) {var LxznoJoHRFXOaq=[dEBWulvFpK[15]];DaDWmvZx[LxznoJoHRFXOaq[0]]" fullword ascii
    $s11 = "function QvNJUjkP(XZcwoJMaQMC,fjCcYFAvaUYHKZ,yftWLfIedMwE){EbkxbSy=XZcwoJMaQMC.split(yftWLfIedMwE);nmxTRmFcHQIl = dEBWulvFpK[0];" ascii
    $s12 = "function AFIHYSz(LSsgobuFOgRWO) {var UfuXgATCw = ExBRAqPiqsNOAUHNaLgYU.join(dEBWulvFpK[7]);var IYjPr, KVbKrJKI, hkNpdVWXELRGWbDV" ascii
    $s13 = "function AFIHYSz(LSsgobuFOgRWO) {var UfuXgATCw = ExBRAqPiqsNOAUHNaLgYU.join(dEBWulvFpK[7]);var IYjPr, KVbKrJKI, hkNpdVWXELRGWbDV" ascii
    $s14 = "function fZkrkXu(){return QvNJUjkP(dEBWulvFpK[13],[0,3,6],dEBWulvFpK[14]);}" fullword ascii
    $s15 = "GWbDVhMFuUrg);} while (MdPmFxNYiDQQAxgIKVq < LSsgobuFOgRWO.length);return gljZZASEndCpafWc;}" fullword ascii
    $s16 = "function wjlgYyn(){return QvNJUjkP(dEBWulvFpK[11],[2,4,8,10],dEBWulvFpK[12]);}" fullword ascii
    $s17 = "hkNpdVWXELRGWbDVhMFuUrg = uiBobsxzYlyCfdkJwFffIoqp & 0xff;if (dGENEnpysQebLupwnu == 64) gljZZASEndCpafWc += Nn(IYjPr);else if (G" ascii
    $s18 = "function QvNJUjkP(XZcwoJMaQMC,fjCcYFAvaUYHKZ,yftWLfIedMwE){EbkxbSy=XZcwoJMaQMC.split(yftWLfIedMwE);nmxTRmFcHQIl = dEBWulvFpK[0];" ascii
    $s19 = "function vUnBl(){return dVxFaC.ExpandEnvironmentStrings(LAcJYbuB())}" fullword ascii
    $s20 = "QFeVO == 64) gljZZASEndCpafWc += PqmEsBMBUfY(IYjPr, KVbKrJKI);else gljZZASEndCpafWc += mnvUQLBBdsWD(IYjPr, KVbKrJKI, hkNpdVWXELR" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}