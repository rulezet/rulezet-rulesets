rule _20160921_5645898a54dfcbd78b32ee6da656f545_20160921_e2cf0a733063_5203 {
  meta:
    description = "datamaliciousorder - from files 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash2       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function" ascii
    $s2 = "function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3 = "uck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo" ascii
    $s4 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuc" ascii
    $s5 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}