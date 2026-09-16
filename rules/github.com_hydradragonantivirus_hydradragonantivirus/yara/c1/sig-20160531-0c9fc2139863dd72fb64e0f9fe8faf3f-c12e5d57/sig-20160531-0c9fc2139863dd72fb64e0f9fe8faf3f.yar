rule sig_20160531_0c9fc2139863dd72fb64e0f9fe8faf3f {
  meta:
    description = "datamaliciousorder - file 20160531_0c9fc2139863dd72fb64e0f9fe8faf3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60befab7f1a8945d97c719b7ff431e0f176953875aa59ce9707e3b1ef13b903a"

  strings:
    $s1  = "var Oqbjsomc=function(){return WScript.CreateObject(gRBjetMVCEdlsdMcGjY[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function iRbzEYXONEVxOtmeHdOVKW(BtmnAktqCJYEoaEVLF,VMavKbtgbZJVYTCvlUrFW){return BtmnAktqCJYEoaEVLF.charAt(VMavKbtgbZJVYTCvlUrFW" ascii
    $s3  = "function iRbzEYXONEVxOtmeHdOVKW(BtmnAktqCJYEoaEVLF,VMavKbtgbZJVYTCvlUrFW){return BtmnAktqCJYEoaEVLF.charAt(VMavKbtgbZJVYTCvlUrFW" ascii
    $s4  = "P=0;rFYVZfxPCbcP<tmKeS.length;rFYVZfxPCbcP++) {RbizaJKu+=Ermhbe[tmKeS[rFYVZfxPCbcP]];}return RbizaJKu.substring(3,RbizaJKu.lengt" ascii
    $s5  = "function Kv(pZcTeRvCCBedGRqX){return String.fromCharCode(pZcTeRvCCBedGRqX);}" fullword ascii
    $s6  = "kEmUVVONmXDQ & 0xff;if (BDMzTWvFawRYTUa == 64) KxWuMgWOiDSvNozmXzt += Kv(MNbKYrkmiXHydpvqiVDsnj);else if (NnzxmLixiKtF == 64) Kx" ascii
    $s7  = "function vzNxLSHLjdZYEF(VIpjaImpcmnUi) {var fVViWtAxmHRUvh = VyiWVwhj.join(gRBjetMVCEdlsdMcGjY[7]);var MNbKYrkmiXHydpvqiVDsnj, p" ascii
    $s8  = "function WQSImisgrOvQpOlWpY(lRljcnazxy,ahlYrTqQNHwesXeShCVLyFx){return String.fromCharCode(lRljcnazxy,ahlYrTqQNHwesXeShCVLyFx);}" ascii
    $s9  = "(byjkmajoEW,0x1,0x0)}function LzpsxH(xknfwaQdqTK,trBXON,UeZDaRx){var HNNgpdMwgjn=xknfwaQdqTK.createtextfile(trBXON,true);HNNgpdM" ascii
    $s10 = "WuMgWOiDSvNozmXzt += WQSImisgrOvQpOlWpY(MNbKYrkmiXHydpvqiVDsnj, pxvUX);else KxWuMgWOiDSvNozmXzt += hLMECXYukcKdBoaWjtHOjt(MNbKYr" ascii
    $s11 = "var MIfPLAYIfkoDhA=function(){return new ActiveXObject(gRBjetMVCEdlsdMcGjY[1]);}();" fullword ascii
    $s12 = "function iZMyhhrYEXIttZ(){return HiKPQMNg(gRBjetMVCEdlsdMcGjY[9],[1,5,7],gRBjetMVCEdlsdMcGjY[10]);}" fullword ascii
    $s13 = "(byjkmajoEW,0x1,0x0)}function LzpsxH(xknfwaQdqTK,trBXON,UeZDaRx){var HNNgpdMwgjn=xknfwaQdqTK.createtextfile(trBXON,true);HNNgpdM" ascii
    $s14 = "function vzNxLSHLjdZYEF(VIpjaImpcmnUi) {var fVViWtAxmHRUvh = VyiWVwhj.join(gRBjetMVCEdlsdMcGjY[7]);var MNbKYrkmiXHydpvqiVDsnj, p" ascii
    $s15 = "function hLMECXYukcKdBoaWjtHOjt(ACLKntiNKXvcYgkNixwYtNc,ARyIvQmJbb,vOMNNBvIHfnA){return String.fromCharCode(ACLKntiNKXvcYgkNixwY" ascii
    $s16 = "kmiXHydpvqiVDsnj, pxvUX, dOURskhaYFYIgl);} while (xloBoZjPHPxX < VIpjaImpcmnUi.length);return KxWuMgWOiDSvNozmXzt;}" fullword ascii
    $s17 = "function ywTWyqsTe(gBgCvswQlCubMqvw,yWFNtkxWMVXWDM){return gBgCvswQlCubMqvw.indexOf(yWFNtkxWMVXWDM);}" fullword ascii
    $s18 = "function GXICeqUBcg(){return HiKPQMNg(gRBjetMVCEdlsdMcGjY[13],[0,3,6],gRBjetMVCEdlsdMcGjY[14]);}" fullword ascii
    $s19 = "function TcecfXVPYDt(){return Oqbjsomc.ExpandEnvironmentStrings(iZMyhhrYEXIttZ())}" fullword ascii
    $s20 = "function hLMECXYukcKdBoaWjtHOjt(ACLKntiNKXvcYgkNixwYtNc,ARyIvQmJbb,vOMNNBvIHfnA){return String.fromCharCode(ACLKntiNKXvcYgkNixwY" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}