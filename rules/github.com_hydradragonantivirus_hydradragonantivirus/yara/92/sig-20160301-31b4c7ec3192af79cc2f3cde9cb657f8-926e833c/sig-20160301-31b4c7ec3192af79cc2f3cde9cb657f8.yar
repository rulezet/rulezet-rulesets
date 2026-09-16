rule sig_20160301_31b4c7ec3192af79cc2f3cde9cb657f8 {
  meta:
    description = "datamaliciousorder - file 20160301_31b4c7ec3192af79cc2f3cde9cb657f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d58bd7d3e9c986267f3af9fa37a40336f67a3358d9926c1698a935aa394377"

  strings:
    $s1  = "var Pq = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(VJBQa);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + siohlDt + \".F\" + dpgpFkxsgu + hogXz + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var iL = true  , SciK = Lgk[7] + \"\" + Lgk[9];" fullword ascii
    $s5  = "ggHvR.open(UJiOA,SVSeE,false);" fullword ascii
    $s6  = "function nFXh(iakHl,AfQhk) {" fullword ascii
    $s7  = "Bpw = u; break; " fullword ascii
    $s8  = "var Lgk = (BBi + \"TTP\" + \" dCweCAw vvkZq XML ream St oPfhWOYH AD qwsrYkX OD\").split(\" \");" fullword ascii
    $s9  = "function TAJM(NXMjm) {" fullword ascii
    $s10 = "if(u>=I.length) {break;}" fullword ascii
    $s11 = "if (ugpxW > 166209-435){return true;} else {return false;}" fullword ascii
    $s12 = "return xnSok.status;" fullword ascii
    $s13 = "function zyxbgKUvz(iGCkz,MHCIj,EmSaj) {" fullword ascii
    $s14 = "function LQkk(xnSok) {" fullword ascii
    $s15 = "function NZGcm(FwseBJ) {" fullword ascii
    $s16 = "return new ActiveXObject(FwseBJ);" fullword ascii
    $s17 = "function XRRX(ugpxW) {" fullword ascii
    $s18 = "function aqcM(fEcHi,EeBDz) {" fullword ascii
    $s19 = "function qzNgNwJxg(PsByYBSdkWw) {" fullword ascii
    $s20 = "return li.ExpandEnvironmentStrings(Pq);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}