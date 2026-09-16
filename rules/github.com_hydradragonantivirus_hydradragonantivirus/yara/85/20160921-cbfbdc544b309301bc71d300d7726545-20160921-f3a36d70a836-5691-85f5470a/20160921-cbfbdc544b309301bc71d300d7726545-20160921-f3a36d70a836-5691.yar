rule _20160921_cbfbdc544b309301bc71d300d7726545_20160921_f3a36d70a836_5691 {
  meta:
    description = "datamaliciousorder - from files 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "urn \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s2 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})" ascii
    $s3 = "ion f000(){return \"Qa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"G" ascii
    $s5 = "ction f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}