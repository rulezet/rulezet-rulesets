rule sig_20151217_6db05730abf6c07b04ceac9c0949d04e {
  meta:
    description = "datamaliciousorder - file 20151217_6db05730abf6c07b04ceac9c0949d04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca204562bdecb0a4444bfdc1a9404103bf19457b704ef5e3b1ff48750ca90cc7"

  strings:
    $s1  = "function NsQsIqiAhkyicuJNY(rvYBU){XIfBKXaFJSL= '';wLQVSyWVGoL=Math.round((Math.pow(Math.sin(789), 2) + Math.pow(Math.cos(789), 2" ascii
    $s2  = "ow(Math.cos(975), 2) - 1)));} BXLVZBtuo[wLQVSyWVGoL]++;}wLQVSyWVGoL++;} return XIfBKXaFJSL}" fullword ascii
    $s3  = "h.pow(Math.cos(249), 2) - 1)); while(true) { if(BXLVZBtuo[wLQVSyWVGoL] > rvYBU[wLQVSyWVGoL].length-(-333+751)/418) { break; } if" ascii
    $s4  = ") - 1));while(true){if (wLQVSyWVGoL >= (-67+907)/140){break;}BXLVZBtuo[wLQVSyWVGoL]=Math.round((Math.pow(Math.sin(249), 2) + Mat" ascii
    $s5  = "function NsQsIqiAhkyicuJNY(rvYBU){XIfBKXaFJSL= '';wLQVSyWVGoL=Math.round((Math.pow(Math.sin(789), 2) + Math.pow(Math.cos(789), 2" ascii
    $s6  = "function AknwqOM(gIlnWaIGTrKCqwLtXWJCTjtxhtHAXcwfLJeQ) {return !eJtphtocDlS(AoXVCDzJGnvotea(gIlnWaIGTrKCqwLtXWJCTjtxhtHAXcwfLJeQ" ascii
    $s7  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s8  = "var C = new Array();C[0]=[];C[0][0]='d';C[0][1]='a';C[0][2]='d';C[0][3]='a';C[0][4]='46';C[0][5]='3d';C[0][6]='42';C[0][7]='14';" ascii
    $s9  = "function AknwqOM(gIlnWaIGTrKCqwLtXWJCTjtxhtHAXcwfLJeQ) {return !eJtphtocDlS(AoXVCDzJGnvotea(gIlnWaIGTrKCqwLtXWJCTjtxhtHAXcwfLJeQ" ascii
    $s10 = "function q(ItnAqCTzfMRa,QeqMaVqvULXhFk){ItnAqCTzfMRa.push(QeqMaVqvULXhFk);}" fullword ascii
    $s11 = "function eJtphtocDlS(cyYOrWMhGSoVLb) {return isNaN(cyYOrWMhGSoVLb);}" fullword ascii
    $s12 = "function gWKybvqPIMbwUXRzm(DcqGkcqUDH,OtccFylaWk) {return parseInt(DcqGkcqUDH,OtccFylaWk);}" fullword ascii
    $s13 = "function PRdXKfCrMfzXapJqUuZqTvOCFmmgtZWcwNIQvelqzZSmzFFcJAtKaq(cZLBaYjBUgRrf,pdxKeeIGRCXJMd){ return tyJAvIl[XmtKaYoD[vqSyn(cZL" ascii
    $s14 = "function vqSyn(WOwcXtWCwBC,hILmVkicinjFM,mRFRLVAz){MPMU=gWKybvqPIMbwUXRzm(WOwcXtWCwBC,hILmVkicinjFM);omUUV=MPMU.toString(mRFRLVA" ascii
    $s15 = "function vqSyn(WOwcXtWCwBC,hILmVkicinjFM,mRFRLVAz){MPMU=gWKybvqPIMbwUXRzm(WOwcXtWCwBC,hILmVkicinjFM);omUUV=MPMU.toString(mRFRLVA" ascii
    $s16 = "function jNuAzBAlcGxs(guaXegUGHRGAo) {return isFinite(guaXegUGHRGAo);}" fullword ascii
    $s17 = "function M(SAsdYHzHixuWvf,vgxrUXJYjyWTs,YfawxBIFYRx) {SAsdYHzHixuWvf[vgxrUXJYjyWTs]=YfawxBIFYRx;}" fullword ascii
    $s18 = "function PRdXKfCrMfzXapJqUuZqTvOCFmmgtZWcwNIQvelqzZSmzFFcJAtKaq(cZLBaYjBUgRrf,pdxKeeIGRCXJMd){ return tyJAvIl[XmtKaYoD[vqSyn(cZL" ascii
    $s19 = "z);return omUUV;}" fullword ascii
    $s20 = "function jcNvEQcwmUUgWQw(uppoZagLJuFGbZwuN,oufOhLuWxgkapCELmZBPLdRlpIEOuSggMM,DDPUvvbJRWBtwhSUAPBOTxhcaQcVTzBgeoE){eval(uppoZagL" ascii

  condition:
    uint16(0) == 0x6d58 and
    8 of them
}