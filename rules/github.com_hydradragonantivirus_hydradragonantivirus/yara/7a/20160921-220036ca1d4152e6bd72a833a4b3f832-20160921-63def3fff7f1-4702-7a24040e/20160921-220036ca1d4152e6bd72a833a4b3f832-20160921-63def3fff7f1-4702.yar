rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_63def3fff7f1_4702 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"

  strings:
    $s1 = "n \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s2 = "\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s3 = "\"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s4 = "function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s5 = "\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}