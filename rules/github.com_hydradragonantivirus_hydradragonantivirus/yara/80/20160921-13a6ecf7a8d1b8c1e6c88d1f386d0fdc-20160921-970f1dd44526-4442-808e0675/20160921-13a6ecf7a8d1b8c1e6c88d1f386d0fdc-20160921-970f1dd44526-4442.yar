rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_970f1dd44526_4442 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash3       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1 = "urn \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s2 = "on f000(){return \"Uo\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"" ascii
    $s3 = "})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s4 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f0" ascii
    $s5 = "on f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}