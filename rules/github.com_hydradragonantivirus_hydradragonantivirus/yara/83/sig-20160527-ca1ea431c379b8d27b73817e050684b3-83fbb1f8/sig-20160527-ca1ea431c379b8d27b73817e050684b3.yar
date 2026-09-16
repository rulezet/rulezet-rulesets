rule sig_20160527_ca1ea431c379b8d27b73817e050684b3 {
  meta:
    description = "datamaliciousorder - file 20160527_ca1ea431c379b8d27b73817e050684b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f64cc3e8b8f8fa07b4399d8561f13d5d91a66849ea972c0599d97b9d18318d6b"

  strings:
    $s1  = "function XmsSXw() {return WScript;}function walbsvBDKP(){return qOtYJORzcMGNE.ExpandEnvironmentStrings(wIHRyzW())}" fullword ascii
    $s2  = "function vpQHjDtxlRqFp(Brejt,oIksFaiNYyEiJqpKA){return Brejt.charAt(oIksFaiNYyEiJqpKA);}" fullword ascii
    $s3  = "n=0;PkvGoWan<luIUYeETlOPu.length;PkvGoWan++) {rPDrEIPKKrCGi+=MqeDXmbomqjld[luIUYeETlOPu[PkvGoWan]];}return rPDrEIPKKrCGi.substri" ascii
    $s4  = "function RlBkETvjnvQMyDW(VcPqjGBPhyNzAXUKkdQuL,LuNrAXkddaQlfEQotncgVdAn){return VcPqjGBPhyNzAXUKkdQuL.indexOf(LuNrAXkddaQlfEQotn" ascii
    $s5  = "function YWNOQ(){return SImdVZPT(APEDnjbSO[10],[2,4,8,10],APEDnjbSO[11]);}" fullword ascii
    $s6  = "function JhtOsqXfK(zcTcWJXKycGsx) {var VTwdKtqyGluvKPVN = nQAZJRfMnyppyfUhq.join(APEDnjbSO[6]);var GVNBdXHAeeeNKSVwiTTtMjc, dkGD" ascii
    $s7  = "artkyCLHtaDx(GVNBdXHAeeeNKSVwiTTtMjc, dkGDTgvxXY);else bvDVVCujngVp += rICjIasJCZVWW(GVNBdXHAeeeNKSVwiTTtMjc, dkGDTgvxXY, ckUBw)" ascii
    $s8  = "function KOkZZeyartkyCLHtaDx(ZOcosqWXcV,XkDuQuNk){return String.fromCharCode(ZOcosqWXcV,XkDuQuNk);}" fullword ascii
    $s9  = "var qOtYJORzcMGNE=function(){return XmsSXw().CreateObject(APEDnjbSO[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function HkFvGwoxDWR(){return SImdVZPT(APEDnjbSO[12],[0,3,6],APEDnjbSO[13]);}" fullword ascii
    $s11 = "function SImdVZPT(ArxrL,luIUYeETlOPu,WvvqrTQMWr){MqeDXmbomqjld=ArxrL.split(WvvqrTQMWr);rPDrEIPKKrCGi = APEDnjbSO[14];for(PkvGoWa" ascii
    $s12 = "ff;if (MALtMaIjTG == 64) bvDVVCujngVp += MB(GVNBdXHAeeeNKSVwiTTtMjc);else if (IvYGqKpCdxiIgNxmKMN == 64) bvDVVCujngVp += KOkZZey" ascii
    $s13 = "function RlBkETvjnvQMyDW(VcPqjGBPhyNzAXUKkdQuL,LuNrAXkddaQlfEQotncgVdAn){return VcPqjGBPhyNzAXUKkdQuL.indexOf(LuNrAXkddaQlfEQotn" ascii
    $s14 = "function JhtOsqXfK(zcTcWJXKycGsx) {var VTwdKtqyGluvKPVN = nQAZJRfMnyppyfUhq.join(APEDnjbSO[6]);var GVNBdXHAeeeNKSVwiTTtMjc, dkGD" ascii
    $s15 = "function SImdVZPT(ArxrL,luIUYeETlOPu,WvvqrTQMWr){MqeDXmbomqjld=ArxrL.split(WvvqrTQMWr);rPDrEIPKKrCGi = APEDnjbSO[14];for(PkvGoWa" ascii
    $s16 = ";} while (XiheYNirLV < zcTcWJXKycGsx.length);return bvDVVCujngVp;}" fullword ascii
    $s17 = "var uBsgxQv=function(){return new ActiveXObject(APEDnjbSO[0]);}();" fullword ascii
    $s18 = "function rICjIasJCZVWW(XHwwR,NNKfjlqyAEmrdjxl,jOtrq){return String.fromCharCode(XHwwR,NNKfjlqyAEmrdjxl,jOtrq);}" fullword ascii
    $s19 = "function MB(awgtVktsIFgVosMdPaUIAgGY){return String.fromCharCode(awgtVktsIFgVosMdPaUIAgGY);}" fullword ascii
    $s20 = ")+APEDnjbSO[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}