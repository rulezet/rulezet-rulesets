rule sig_20160531_ab8669db26a39d50bfa2f269e34f442d {
  meta:
    description = "datamaliciousorder - file 20160531_ab8669db26a39d50bfa2f269e34f442d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24693465eab08985deb9b5ecab7b65f829344387eebca79ae4e005ec7ecce663"

  strings:
    $s1  = "var GwoETVhIsjXPv=function(){return WScript.CreateObject(TwPedNZZxmvJgYBMfSDYeCFQ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s2  = "function FGrIVLEXjAHbKvp(kUYUTGVRaVYbUWlEh,uvqkDbqPpTvBmBhUZEDTHLto){return kUYUTGVRaVYbUWlEh.charAt(uvqkDbqPpTvBmBhUZEDTHLto);}" ascii
    $s3  = "function NrGSQemTFlECdHwvRR(PNSzpBNgtkuME,glWvwiHiztgIgZ){return PNSzpBNgtkuME.indexOf(glWvwiHiztgIgZ);}" fullword ascii
    $s4  = "(mAoBiUeOBqGP=0;mAoBiUeOBqGP<QHpwpuNYYm.length;mAoBiUeOBqGP++) {gNVze+=jMjffVpSk[QHpwpuNYYm[mAoBiUeOBqGP]];}return gNVze.substri" ascii
    $s5  = "function VyPPdJ(drFOLRclRDrOt) {var wglvYYxonQYLDCXpSMK = LiTnqhkvhUcnZCzaEzj.join(TwPedNZZxmvJgYBMfSDYeCFQ[7]);var UmbsGMYI, uD" ascii
    $s6  = "function zKATuIqWmoYhYaUiweQt(iLCfAzmCkrwE,QAClUzKSoCZM,GigNAwhTHDtiE){return String.fromCharCode(iLCfAzmCkrwE,QAClUzKSoCZM,GigN" ascii
    $s7  = "function vEJwKQWOFb(){return JvGqeCpnCh(TwPedNZZxmvJgYBMfSDYeCFQ[13],[0,3,6],TwPedNZZxmvJgYBMfSDYeCFQ[14]);}" fullword ascii
    $s8  = "function cM(RLbvCnzmDDp){return String.fromCharCode(RLbvCnzmDDp);}" fullword ascii
    $s9  = "function mWQbPmUJtirdG(){return JvGqeCpnCh(TwPedNZZxmvJgYBMfSDYeCFQ[9],[1,5,7],TwPedNZZxmvJgYBMfSDYeCFQ[10]);}" fullword ascii
    $s10 = "function RYAAyycifreTBwCifsoI(oCfKFrqjhAnXe,CIlKdYVtMbzXYlOFjXCBnQ){return String.fromCharCode(oCfKFrqjhAnXe,CIlKdYVtMbzXYlOFjXC" ascii
    $s11 = "function RYAAyycifreTBwCifsoI(oCfKFrqjhAnXe,CIlKdYVtMbzXYlOFjXCBnQ){return String.fromCharCode(oCfKFrqjhAnXe,CIlKdYVtMbzXYlOFjXC" ascii
    $s12 = "function bMIHvWUlnUwuV(){return GwoETVhIsjXPv.ExpandEnvironmentStrings(mWQbPmUJtirdG())}" fullword ascii
    $s13 = "function HiPegKYOCgb(BgWii,IyKYXyQNGxHwoP) {var zGbTqGvlQ=[TwPedNZZxmvJgYBMfSDYeCFQ[15]];BgWii[zGbTqGvlQ[0]]" fullword ascii
    $s14 = "function GdQOEoEgubw(){return JvGqeCpnCh(TwPedNZZxmvJgYBMfSDYeCFQ[11],[2,4,8,10],TwPedNZZxmvJgYBMfSDYeCFQ[12]);}" fullword ascii
    $s15 = "(IyKYXyQNGxHwoP,0x1,0x0)}function ozXIpSojDQUHkO(GNYpLoKISYUTs,LzJZWasZaBp,PeTxNTOQJ){var HtNRGjELGvvoA=GNYpLoKISYUTs.createtext" ascii
    $s16 = "function zKATuIqWmoYhYaUiweQt(iLCfAzmCkrwE,QAClUzKSoCZM,GigNAwhTHDtiE){return String.fromCharCode(iLCfAzmCkrwE,QAClUzKSoCZM,GigN" ascii
    $s17 = "kAZbWNvHePxHgaa += zKATuIqWmoYhYaUiweQt(UmbsGMYI, uDaKYMa, XWkSKTTZQUhcPbaMwVyt);} while (mFbAmhgVhyXueTKkZeHGhRn < drFOLRclRDrO" ascii
    $s18 = "file(LzJZWasZaBp,true);HtNRGjELGvvoA.WriteLine(PeTxNTOQJ);HtNRGjELGvvoA.Close();}" fullword ascii
    $s19 = "HePxHgaa += cM(UmbsGMYI);else if (mUQyYn == 64) uEiNHqNokAZbWNvHePxHgaa += RYAAyycifreTBwCifsoI(UmbsGMYI, uDaKYMa);else uEiNHqNo" ascii
    $s20 = "(IyKYXyQNGxHwoP,0x1,0x0)}function ozXIpSojDQUHkO(GNYpLoKISYUTs,LzJZWasZaBp,PeTxNTOQJ){var HtNRGjELGvvoA=GNYpLoKISYUTs.createtext" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}